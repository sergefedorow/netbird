package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	"github.com/netbirdio/netbird/shared/management/proto"
)

type capturingURLGenerator struct {
	redirectURL string
}

func (c *capturingURLGenerator) GetOIDCURL(_ context.Context, in *proto.GetOIDCURLRequest, _ ...grpc.CallOption) (*proto.GetOIDCURLResponse, error) {
	c.redirectURL = in.GetRedirectUrl()
	return &proto.GetOIDCURLResponse{Url: "https://idp.example.com/auth"}, nil
}

func TestOIDCAuthenticate_RedirectURLKeepsRequestedURL(t *testing.T) {
	tests := []struct {
		name   string
		target string
		want   string
	}{
		{
			name:   "plain path",
			target: "/search",
			want:   "https://app.example.com/search",
		},
		{
			name:   "query string",
			target: "/details?nodeRef=workspace://SpacesStore/abc&view=full",
			want:   "https://app.example.com/details?nodeRef=workspace://SpacesStore/abc&view=full",
		},
		{
			name:   "encoded path and query",
			target: "/a%2Fb/?q=x%20y",
			want:   "https://app.example.com/a%2Fb/?q=x%20y",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &capturingURLGenerator{}
			scheme := NewOIDC(client, "svc", "acc", "https")

			r := httptest.NewRequest(http.MethodGet, tt.target, nil)
			r.Host = "app.example.com"

			token, promptData, err := scheme.Authenticate(r)
			require.NoError(t, err)
			assert.Empty(t, token, "An unauthenticated request must not yield a token")
			assert.NotEmpty(t, promptData, "The IdP URL should be returned as prompt data")
			assert.Equal(t, tt.want, client.redirectURL, "Redirect URL should match the requested URL")
		})
	}
}
