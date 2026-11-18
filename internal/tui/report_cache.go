package tui

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/Zagorsky17/ServerSecurityGo/internal/model"
)

type systemReport struct {
	Findings []model.SystemFinding `json:"findings"`
}
type cachedReport[T any] struct {
	etag  string
	value T
	ready bool
}

func fetchReport[T any](r *RemoteSource, path string, cache *cachedReport[T]) (T, error) {
	resp, err := r.request(path, cache.etag)
	if err != nil {
		*cache = cachedReport[T]{}
		return cache.value, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		if cache.ready && cache.etag != "" {
			return cache.value, nil
		}
		*cache = cachedReport[T]{}
		return cache.value, errors.New(resp.Status)
	}
	var value T
	if err := json.NewDecoder(resp.Body).Decode(&value); err != nil {
		*cache = cachedReport[T]{}
		return cache.value, err
	}
	*cache = cachedReport[T]{etag: resp.Header.Get("ETag"), value: value, ready: true}
	return value, nil
}
