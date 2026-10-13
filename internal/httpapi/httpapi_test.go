package httpapi_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/dimitrijegasic/seal-gate/internal/authorization"
	"github.com/dimitrijegasic/seal-gate/internal/identity"
	"github.com/dimitrijegasic/seal-gate/internal/system"
)

const contentTypeJSON = "application/json"

type errorBody struct {
	Errors []string `json:"errors"`
}

type initBody struct {
	Shares    []string `json:"shares"`
	RootToken string   `json:"root_token"`
}

type statusBody struct {
	Initialized bool `json:"initialized"`
	Sealed      bool `json:"sealed"`
	Shares      int  `json:"shares"`
	Threshold   int  `json:"threshold"`
	Progress    int  `json:"progress"`
}

type fakeSystem struct {
	initConfig   system.SealConfiguration
	initResult   system.InitResult
	initErr      error
	unsealShare  []byte
	unsealGiven  []byte
	unsealResult system.Status
	unsealErr    error
	sealed       bool
	statusResult system.Status
	statusErr    error
}

func (f *fakeSystem) Init(ctx context.Context, cfg system.SealConfiguration) (system.InitResult, error) {
	f.initConfig = cfg
	return f.initResult, f.initErr
}

func (f *fakeSystem) Status(ctx context.Context) (system.Status, error) {
	return f.statusResult, f.statusErr
}

func (f *fakeSystem) Unseal(ctx context.Context, share []byte) (system.Status, error) {
	f.unsealShare = bytes.Clone(share)
	f.unsealGiven = share
	return f.unsealResult, f.unsealErr
}

func (f *fakeSystem) Seal(ctx context.Context) {
	f.sealed = true
}

type secretBody struct {
	Value string `json:"value"`
}

type listBody struct {
	Paths []string `json:"paths"`
}

type fakeSecret struct {
	path       string // the last path Put, Get or Delete got
	putValue   []byte
	getValue   []byte
	listPrefix string
	listPaths  []string
	err        error
}

func (f *fakeSecret) Put(ctx context.Context, path string, value []byte) error {
	f.path = path
	f.putValue = bytes.Clone(value)
	return f.err
}

func (f *fakeSecret) Get(ctx context.Context, path string) ([]byte, error) {
	f.path = path
	return f.getValue, f.err
}

func (f *fakeSecret) Delete(ctx context.Context, path string) error {
	f.path = path
	return f.err
}

func (f *fakeSecret) List(ctx context.Context, prefix string) ([]string, error) {
	f.listPrefix = prefix
	return f.listPaths, f.err
}

type policyBody struct {
	Rules []ruleBody `json:"rules"`
}

type ruleBody struct {
	Path         string   `json:"path"`
	Capabilities []string `json:"capabilities"`
}

type fakePolicy struct {
	name      string // the last name Get or Delete got
	putPolicy authorization.Policy
	getPolicy authorization.Policy
	err       error
}

func (f *fakePolicy) Put(ctx context.Context, policy authorization.Policy) error {
	f.putPolicy = policy
	return f.err
}

func (f *fakePolicy) Get(ctx context.Context, name string) (authorization.Policy, error) {
	f.name = name
	return f.getPolicy, f.err
}

func (f *fakePolicy) Delete(ctx context.Context, name string) error {
	f.name = name
	return f.err
}

type entityBody struct {
	Policies []string `json:"policies"`
	Groups   []string `json:"groups"`
}

type createEntityBody struct {
	ID string `json:"id"`
}

type fakeEntity struct {
	id        string // the last ID Get, Delete or CreateToken got
	created   identity.Entity
	createID  string
	getEntity identity.Entity
	updated   identity.Entity
	token     []byte
	err       error
}

func (f *fakeEntity) CreateEntity(ctx context.Context, entity identity.Entity) (string, error) {
	f.created = entity
	return f.createID, f.err
}

func (f *fakeEntity) GetEntity(ctx context.Context, id string) (identity.Entity, error) {
	f.id = id
	return f.getEntity, f.err
}

func (f *fakeEntity) UpdateEntity(ctx context.Context, entity identity.Entity) error {
	f.updated = entity
	return f.err
}

func (f *fakeEntity) DeleteEntity(ctx context.Context, id string) error {
	f.id = id
	return f.err
}

func (f *fakeEntity) CreateToken(ctx context.Context, entityID string) ([]byte, error) {
	f.id = entityID
	return f.token, f.err
}

type tokenBody struct {
	Token string `json:"token"`
}

func do(t *testing.T, h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", contentTypeJSON)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.NewDecoder(rec.Body).Decode(&v); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	return v
}

// assertError checks the status and that the body carries exactly one message.
func assertError(t *testing.T, rec *httptest.ResponseRecorder, status int, message string) {
	t.Helper()
	if rec.Code != status {
		t.Errorf("status: got %d, want %d: %s", rec.Code, status, rec.Body)
	}

	got := decode[errorBody](t, rec)
	want := []string{message}
	if !slices.Equal(got.Errors, want) {
		t.Errorf("message: got %v, want %v", got.Errors, want)
	}
}
