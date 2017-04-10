package translate

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTranslateTo(t *testing.T) {
	text := TranslateTo("IP address", "pl")
	assert.Equal(t, "Adres IP", text)
}

func TestSetLanguages(t *testing.T) {
	text := Translate("IP address")
	assert.Equal(t, "IP address", text)

	err := SetLang("pl")
	assert.NoError(t, err)

	text = Translate("IP address")
	assert.Equal(t, "Adres IP", text)
}

func TestUnsuportedLanguage(t *testing.T) {
	err := SetLang("xx")
	assert.Error(t, err)
}
