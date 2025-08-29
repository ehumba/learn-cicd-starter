package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	type test struct {
		name    string
		input   http.Header
		wantKey string
		wantErr error
	}
	tests := []test{
		{name: "No authorization",
			input:   http.Header{"Authorization": []string{""}},
			wantKey: "",
			wantErr: ErrNoAuthHeaderIncluded},
		{name: "No header",
			input:   http.Header{},
			wantKey: "",
			wantErr: ErrNoAuthHeaderIncluded},
		{name: "wrong format",
			input:   http.Header{"Authorization": []string{"Some invalid format"}},
			wantKey: "",
			wantErr: errors.New("malformed authorization header")},
		{name: "valid",
			input:   http.Header{"Authorization": []string{"ApiKey 123"}},
			wantKey: "123",
			wantErr: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, gotErr := GetAPIKey(tt.input)

			if gotKey != tt.wantKey {
				t.Errorf("expected key %q, got %q", tt.wantKey, gotKey)
			}

			if (gotErr == nil) != (tt.wantErr == nil) {
				t.Fatalf("expected error %v, got %v", tt.wantErr, gotErr)
			}

			if gotErr != nil && gotErr.Error() != tt.wantErr.Error() {
				t.Errorf("expected error %q, got %q", tt.wantErr, gotErr)
			}
		})
	}

}
