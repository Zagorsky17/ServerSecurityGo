package model

import (
	"testing"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
)

// TestNamesTranslated: у каждой категории признаков и каждого типа
// событий есть названия в каталоге (интерфейсы собирают ключ из значения).
func TestNamesTranslated(t *testing.T) {
	for _, c := range []string{CatLocation, CatIntegrity, CatMasquerade, CatChain, CatNetwork, CatContent,
		CatBehavior, CatEnvironment, CatPrivilege, CatPersistence, CatInfo} {
		if !i18n.Has("cat." + c) {
			t.Errorf("нет перевода категории %s", c)
		}
	}
	for _, e := range []string{EvBaseline, EvStarted, EvExited, EvChanged, EvRiskUp, EvRiskDown, EvFinding, EvListen, EvSystem} {
		if !i18n.Has("event."+e) || !i18n.Has("tui.event."+e) {
			t.Errorf("нет перевода типа события %s", e)
		}
	}
}
