package main

import (
	"context"
	"doltdesk-api/db/utils"
	"fmt"
)

type contextKey string

const (
	userContextKey contextKey = "user"
	dbContextKey              = "database"
)

func contextWithUser(ctx context.Context, user *User) context.Context {
	return context.WithValue(ctx, userContextKey, user)
}

func userFromContext(ctx context.Context) (*User, error) {
	user, ok := ctx.Value(userContextKey).(*User)

	if !ok {
		return nil, fmt.Errorf("object stored at key '%s' is not a user", userContextKey)
	}

	return user, nil
}

func contextWithDB(ctx context.Context, db *utils.DBProvider) context.Context {
	return context.WithValue(ctx, dbContextKey, db)
}

func dbFromContext(ctx context.Context) (*utils.DBProvider, error) {
	db, ok := ctx.Value(dbContextKey).(*utils.DBProvider)
	if !ok {
		return nil, fmt.Errorf("object stored at key '%s' is not a database provider", dbContextKey)
	}

	return db, nil
}
