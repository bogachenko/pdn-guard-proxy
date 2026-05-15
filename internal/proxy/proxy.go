package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/lumiforge/pdn-guard-proxy/internal/config"
	pdd "github.com/lumiforge/pdn-guard-proxy/internal/pdn"
)

type Handler struct {
	cfg            config.Config
	targetURL      *url.URL
	natasha        *pdd.NatashaClient
	reverseProxy   *httputil.ReverseProxy
	blockedMessage []byte
}

type blockedResponse struct {
	Error   string   `json:"error"`
	Message string   `json:"message"`
	Reason  string   `json:"reason"`
	Types   []string `json:"types,omitempty"`
}

func NewHandler(cfg config.Config, natasha *pdd.NatashaClient) (*Handler, error) {
	targetURL, err := url.Parse(cfg.TargetBaseURL)
	if err != nil {
		return nil, err
	}

	rp := httputil.NewSingleHostReverseProxy(targetURL)

	originalDirector := rp.Director
	rp.Director = func(req *http.Request) {
		originalDirector(req)

		req.Host = targetURL.Host
		req.URL.Scheme = targetURL.Scheme
		req.URL.Host = targetURL.Host

		req.Header.Del("X-Forwarded-For")
		req.Header.Del("X-Real-IP")
		req.Header.Del("Forwarded")
	}

	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("proxy upstream error: method=%s path=%s err=%v", r.Method, r.URL.Path, err)
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
	}

	return &Handler{
		cfg:          cfg,
		targetURL:    targetURL,
		natasha:      natasha,
		reverseProxy: rp,
	}, nil
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Body == nil {
		h.reverseProxy.ServeHTTP(w, r)
		return
	}

	body, err := readLimitedBody(r.Body, h.cfg.MaxBodyBytes)
	if err != nil {
		writeJSON(w, http.StatusRequestEntityTooLarge, blockedResponse{
			Error:   "request_body_too_large",
			Message: "Размер запроса превышает допустимый лимит.",
			Reason:  "body_limit_exceeded",
		})
		return
	}

	inspectionText := buildInspectionText(r, body)

	ctx, cancel := context.WithTimeout(r.Context(), h.cfg.RequestTimeout)
	defer cancel()

	decision, err := pdd.CheckBeforeForward(ctx, inspectionText, h.natasha)
	if err != nil || !decision.Allowed {
		if errors.Is(err, pdd.ErrPersonalDataDetected) {
			writeJSON(w, http.StatusUnprocessableEntity, blockedResponse{
				Error:   "personal_data_detected",
				Message: "Запрос заблокирован. Удалите персональные данные и повторите попытку.",
				Reason:  decision.Reason,
				Types:   decision.EntityTypes,
			})
			return
		}

		writeJSON(w, http.StatusServiceUnavailable, blockedResponse{
			Error:   "pii_check_unavailable",
			Message: "Запрос временно заблокирован: проверка персональных данных недоступна.",
			Reason:  decision.Reason,
		})
		return
	}

	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	r.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}

	h.reverseProxy.ServeHTTP(w, r)
}

func readLimitedBody(body io.ReadCloser, limit int64) ([]byte, error) {
	defer body.Close()

	var buf bytes.Buffer
	_, err := io.Copy(&buf, io.LimitReader(body, limit+1))
	if err != nil {
		return nil, err
	}

	if int64(buf.Len()) > limit {
		return nil, errors.New("body too large")
	}

	return buf.Bytes(), nil
}

func buildInspectionText(r *http.Request, body []byte) string {
	var b strings.Builder

	if r.URL.RawQuery != "" {
		b.WriteString(r.URL.RawQuery)
		b.WriteString("\n")
	}

	contentType := strings.ToLower(r.Header.Get("Content-Type"))

	if strings.Contains(contentType, "application/json") ||
		strings.Contains(contentType, "text/") ||
		strings.Contains(contentType, "application/x-www-form-urlencoded") ||
		contentType == "" {
		b.Write(body)
	}

	return b.String()
}

func writeJSON(w http.ResponseWriter, status int, payload blockedResponse) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("write json error: %v", err)
	}
}
