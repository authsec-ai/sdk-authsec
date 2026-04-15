package authsec

import "context"

type principalCtxKey struct{}

func WithPrincipal(ctx context.Context, principal *Principal) context.Context {
	return context.WithValue(ctx, principalCtxKey{}, principal)
}

func PrincipalFromContext(ctx context.Context) (*Principal, bool) {
	principal, ok := ctx.Value(principalCtxKey{}).(*Principal)
	return principal, ok && principal != nil
}
