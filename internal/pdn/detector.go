package pdn

import (
	"context"
	"errors"
	"net/mail"
	"regexp"
	"strings"
	"unicode"

	"github.com/nyaruka/phonenumbers"
	"golang.org/x/text/unicode/norm"
)

var ErrPersonalDataDetected = errors.New("personal data detected")

type Decision struct {
	Allowed     bool     `json:"allowed"`
	Reason      string   `json:"reason"`
	EntityTypes []string `json:"entity_types"`
}

type Detection struct {
	Type string `json:"type"`
}

var (
	spacesRe = regexp.MustCompile(`\s+`)

	addressContextRe = regexp.MustCompile(`(?iu)\b(?:адрес|доставка|проживает|живет|живёт|зарегистрирован|регистрация|прописка|г\.|город|ул\.|улица|проспект|пр-т|пер\.|переулок|д\.|дом|кв\.|квартира|офис|корпус|строение|шоссе|набережная|область|район)\b`)

	organizationPersonalContextRe = regexp.MustCompile(`(?iu)\b(?:сотрудник|работник|директор|бухгалтер|менеджер|клиент|пациент|контактное\s+лицо|представитель|заявитель|получатель|покупатель|должность|зарплата|уволен|увольнение|договор|заказ|заявка|тикет)\b`)

	emailRe = regexp.MustCompile(`(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b`)

	passportRFRe = regexp.MustCompile(`\b\d{2}\s?\d{2}\s?\d{6}\b`)

	snilsRe = regexp.MustCompile(`\b\d{3}[-\s]?\d{3}[-\s]?\d{3}[-\s]?\d{2}\b`)

	innRe = regexp.MustCompile(`\b(?:\d{10}|\d{12})\b`)

	cardCandidateRe = regexp.MustCompile(`\b(?:\d[ -]?){13,19}\b`)

	russianPhoneCandidateRe = regexp.MustCompile(`(?:\+7|8)?[\s\-()]*(?:\d[\s\-()]*){10}`)

	dateRe = regexp.MustCompile(`\b(?:0?[1-9]|[12]\d|3[01])[.\-/](?:0?[1-9]|1[0-2])[.\-/](?:19\d{2}|20\d{2})\b`)

	ipv4Re = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)

	jwtRe = regexp.MustCompile(`\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b`)

	apiKeyRe = regexp.MustCompile(`(?i)\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|secret|bearer)\s*[:=]\s*[a-z0-9._\-]{16,}\b`)

	vehiclePlateRe = regexp.MustCompile(`(?iu)\b[авекмнорстухabekmhopctyx]\s?\d{3}\s?[авекмнорстухabekmhopctyx]{2}\s?\d{2,3}\b`)

	vinRe = regexp.MustCompile(`(?i)\b[A-HJ-NPR-Z0-9]{17}\b`)

	birthDateContextRe = regexp.MustCompile(`(?iu)\b(?:дата\s+рождения|др|родился|родилась|возраст|лет)\b`)

	documentDateContextRe = regexp.MustCompile(`(?iu)\b(?:паспорт|выдан|действителен|снилс|инн|полис|омс|дмс|водительское|удостоверение)\b`)

	medicalDateContextRe = regexp.MustCompile(`(?iu)\b(?:пациент|диагноз|анализ|при[её]м|госпитализация|лечение|рецепт|беременность|инвалидность)\b`)
)

func CheckBeforeForward(ctx context.Context, text string, natasha *NatashaClient) (Decision, error) {
	normalized := Normalize(text)

	structured := DetectStructuredPII(normalized)
	if len(structured) > 0 {
		return Decision{
			Allowed:     false,
			Reason:      "structured_pii_detected",
			EntityTypes: detectionTypes(structured),
		}, ErrPersonalDataDetected
	}

	ner, err := natasha.Analyze(ctx, normalized)
	if err != nil {
		return Decision{
			Allowed: false,
			Reason:  "pii_analyzer_unavailable",
		}, err
	}

	riskyNER := riskyNERTypes(normalized, ner.Entities)
	if len(riskyNER) > 0 {
		return Decision{
			Allowed:     false,
			Reason:      "named_entity_detected",
			EntityTypes: riskyNER,
		}, ErrPersonalDataDetected
	}

	return Decision{
		Allowed: true,
		Reason:  "no_pii_detected",
	}, nil
}

func Normalize(text string) string {
	text = norm.NFKC.String(text)
	text = strings.TrimSpace(text)
	text = spacesRe.ReplaceAllString(text, " ")
	return text
}

func DetectStructuredPII(text string) []Detection {
	detections := make([]Detection, 0)

	for _, value := range emailRe.FindAllString(text, -1) {
		if _, err := mail.ParseAddress(value); err == nil {
			detections = append(detections, Detection{Type: "EMAIL"})
		}
	}

	for _, value := range russianPhoneCandidateRe.FindAllString(text, -1) {
		number, err := phonenumbers.Parse(value, "RU")
		if err == nil && phonenumbers.IsValidNumber(number) {
			detections = append(detections, Detection{Type: "PHONE"})
		}
	}

	for range passportRFRe.FindAllString(text, -1) {
		detections = append(detections, Detection{Type: "PASSPORT_RF"})
	}

	for _, value := range snilsRe.FindAllString(text, -1) {
		if validSNILS(value) {
			detections = append(detections, Detection{Type: "SNILS"})
		}
	}

	for _, value := range innRe.FindAllString(text, -1) {
		if validINN(value) {
			detections = append(detections, Detection{Type: "INN"})
		}
	}

	for _, value := range cardCandidateRe.FindAllString(text, -1) {
		digits := onlyDigits(value)
		if len(digits) >= 13 && len(digits) <= 19 && validLuhn(digits) {
			detections = append(detections, Detection{Type: "BANK_CARD"})
		}
	}

	for range dateRe.FindAllString(text, -1) {
		detections = append(detections, Detection{Type: "DATE"})
	}

	for _, value := range ipv4Re.FindAllString(text, -1) {
		if validIPv4(value) {
			detections = append(detections, Detection{Type: "IP_ADDRESS"})
		}
	}

	for range jwtRe.FindAllString(text, -1) {
		detections = append(detections, Detection{Type: "JWT"})
	}

	for range apiKeyRe.FindAllString(text, -1) {
		detections = append(detections, Detection{Type: "SECRET"})
	}

	for range vehiclePlateRe.FindAllString(text, -1) {
		detections = append(detections, Detection{Type: "VEHICLE_PLATE"})
	}

	for range vinRe.FindAllString(text, -1) {
		detections = append(detections, Detection{Type: "VIN"})
	}

	return dedupeDetections(detections)
}

func riskyNERTypes(text string, entities []NatashaEntity) []string {
	result := make([]string, 0)
	hasPER := false

	for _, entity := range entities {
		if entity.Type == "PER" {
			hasPER = true
			result = append(result, "PER")
		}
	}

	for _, entity := range entities {
		switch entity.Type {
		case "LOC":
			if hasPER || hasAddressContext(text) {
				result = append(result, "LOC")
			}

		case "ORG":
			if hasPER || hasPersonalOrganizationContext(text) {
				result = append(result, "ORG")
			}

		case "DATE":
			if hasSensitiveDateContext(text) {
				result = append(result, "DATE")
			}
		}
	}

	return dedupeStrings(result)
}

func hasSensitiveDateContext(text string) bool {
	return birthDateContextRe.MatchString(text) ||
		documentDateContextRe.MatchString(text) ||
		medicalDateContextRe.MatchString(text)
}

func hasAddressContext(text string) bool {
	return addressContextRe.MatchString(text)
}

func hasPersonalOrganizationContext(text string) bool {
	return organizationPersonalContextRe.MatchString(text)
}

func detectionTypes(detections []Detection) []string {
	result := make([]string, 0, len(detections))
	for _, detection := range detections {
		result = append(result, detection.Type)
	}
	return dedupeStrings(result)
}

func dedupeDetections(items []Detection) []Detection {
	seen := make(map[string]bool)
	result := make([]Detection, 0, len(items))

	for _, item := range items {
		if !seen[item.Type] {
			seen[item.Type] = true
			result = append(result, item)
		}
	}

	return result
}

func dedupeStrings(items []string) []string {
	seen := make(map[string]bool)
	result := make([]string, 0, len(items))

	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}

	return result
}

func onlyDigits(s string) string {
	var b strings.Builder

	for _, r := range s {
		if unicode.IsDigit(r) {
			b.WriteRune(r)
		}
	}

	return b.String()
}

func validLuhn(s string) bool {
	sum := 0
	alternate := false

	for i := len(s) - 1; i >= 0; i-- {
		n := int(s[i] - '0')

		if alternate {
			n *= 2
			if n > 9 {
				n -= 9
			}
		}

		sum += n
		alternate = !alternate
	}

	return sum%10 == 0
}

func validSNILS(s string) bool {
	digits := onlyDigits(s)
	if len(digits) != 11 {
		return false
	}

	sum := 0
	for i := 0; i < 9; i++ {
		sum += int(digits[i]-'0') * (9 - i)
	}

	check := 0
	if sum < 100 {
		check = sum
	} else if sum == 100 || sum == 101 {
		check = 0
	} else {
		check = sum % 101
		if check == 100 {
			check = 0
		}
	}

	actual := int(digits[9]-'0')*10 + int(digits[10]-'0')
	return check == actual
}

func validINN(s string) bool {
	digits := onlyDigits(s)

	if len(digits) == 10 {
		return innChecksum(digits, []int{2, 4, 10, 3, 5, 9, 4, 6, 8}) == int(digits[9]-'0')
	}

	if len(digits) == 12 {
		return innChecksum(digits, []int{7, 2, 4, 10, 3, 5, 9, 4, 6, 8}) == int(digits[10]-'0') &&
			innChecksum(digits, []int{3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8}) == int(digits[11]-'0')
	}

	return false
}

func innChecksum(digits string, coeffs []int) int {
	sum := 0

	for i, coeff := range coeffs {
		sum += int(digits[i]-'0') * coeff
	}

	return (sum % 11) % 10
}

func validIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}

	for _, part := range parts {
		if part == "" || len(part) > 3 {
			return false
		}

		n := 0
		for _, r := range part {
			if r < '0' || r > '9' {
				return false
			}
			n = n*10 + int(r-'0')
		}

		if n > 255 {
			return false
		}
	}

	return true
}
