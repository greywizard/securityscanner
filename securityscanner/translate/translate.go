package translate

import "errors"

var translations = map[Language]map[string]string{}
var currentLang Language
var availableLangs = map[Language]bool{"en": true, "pl": true}

type Language string

func init() {
	currentLang = "en"
}

func SetLang(lang Language) (err error) {
	if _, ok := availableLangs[lang]; !ok {
		err = errors.New(string(lang) + " is not supported language")
	} else {
		currentLang = lang
	}

	return err
}

func GetLang() Language {
	return currentLang
}

func TranslateTo(text string, lang Language) string {
	if language, ok := translations[lang]; ok {
		if translation, ok2 := language[text]; ok2 {
			return translation
		}
	}
	return text
}
func Translate(text string) string {
	return TranslateTo(text, currentLang)
}
