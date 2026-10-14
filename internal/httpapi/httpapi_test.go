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
	"time"

	"github.com/dimitrijegasic/seal-gate/internal/audit"
	"github.com/dimitrijegasic/seal-gate/internal/authorization"
	"github.com/dimitrijegasic/seal-gate/internal/httpapi"
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

// fakeAuthenticator accepts every token as principal unless err is set.
type fakeAuditor struct {
	events []audit.Event
	errs   map[audit.Kind]error // what Record returns, per kind of event
}

func (f *fakeAuditor) Record(ctx context.Context, event audit.Event) error {
	f.events = append(f.events, event)
	return f.errs[event.Kind]
}

// fakeClock returns next, then moves it on a second, so two readings differ.
type fakeClock struct{ next time.Time }

func (c *fakeClock) Now() time.Time {
	now := c.next
	c.next = c.next.Add(time.Second)
	return now
}

// newRouter fills in an auditor and a clock when a test does not care about them.
func newRouter(h *httpapi.Handlers) http.Handler {
	if h.Auditor == nil {
		h.Auditor = &fakeAuditor{}
	}
	if h.Clock == nil {
		h.Clock = &fakeClock{}
	}
	return httpapi.NewRouter(h)
}

type fakeAuthenticator struct {
	token     []byte // a copy of the last token
	given     []byte // the last token as given, to check it is cleared
	principal authorization.Principal
	err       error
}

func (f *fakeAuthenticator) Authenticate(ctx context.Context, token []byte) (authorization.Principal, error) {
	f.token = bytes.Clone(token)
	f.given = token
	if f.err != nil {
		return authorization.Principal{}, f.err
	}
	return f.principal, nil
}

type fakeSystem struct {
	initConfig   system.SealConfiguration
	initResult   system.InitResult
	initErr      error
	unsealShare  []byte
	unsealGiven  []byte
	unsealResult system.Status
	unsealErr    error
	resetResult  system.Status
	resetErr     error
	sealed       bool
	principal    authorization.Principal // the principal Seal got
	sealErr      error
	statusResult system.Status
	statusErr    error
	statusCalls  int
}

func (f *fakeSystem) Init(ctx context.Context, cfg system.SealConfiguration) (system.InitResult, error) {
	f.initConfig = cfg
	return f.initResult, f.initErr
}

func (f *fakeSystem) Status(ctx context.Context) (system.Status, error) {
	f.statusCalls++
	return f.statusResult, f.statusErr
}

func (f *fakeSystem) Unseal(ctx context.Context, share []byte) (system.Status, error) {
	f.unsealShare = bytes.Clone(share)
	f.unsealGiven = share
	return f.unsealResult, f.unsealErr
}

func (f *fakeSystem) ResetUnseal(ctx context.Context) (system.Status, error) {
	return f.resetResult, f.resetErr
}

func (f *fakeSystem) Seal(ctx context.Context, principal authorization.Principal) error {
	f.principal = principal
	f.sealed = true
	return f.sealErr
}

type secretBody struct {
	Value string `json:"value"`
}

type listBody struct {
	Paths []string `json:"paths"`
}

type fakeSecret struct {
	principal  authorization.Principal // the last principal any method got
	path       string                  // the last path any method but List got
	putValue   []byte
	getValue   []byte
	listPrefix string
	listPaths  []string
	genLength  int
	genValue   []byte
	rotValue   []byte
	err        error
}

func (f *fakeSecret) Rotate(ctx context.Context, principal authorization.Principal, path string) ([]byte, error) {
	f.principal = principal
	f.path = path
	return f.rotValue, f.err
}

func (f *fakeSecret) Generate(ctx context.Context, principal authorization.Principal, path string, length int) ([]byte, error) {
	f.principal = principal
	f.path = path
	f.genLength = length
	return f.genValue, f.err
}

func (f *fakeSecret) Put(ctx context.Context, principal authorization.Principal, path string, value []byte) error {
	f.principal = principal
	f.path = path
	f.putValue = bytes.Clone(value)
	return f.err
}

func (f *fakeSecret) Get(ctx context.Context, principal authorization.Principal, path string) ([]byte, error) {
	f.principal = principal
	f.path = path
	return f.getValue, f.err
}

func (f *fakeSecret) Delete(ctx context.Context, principal authorization.Principal, path string) error {
	f.principal = principal
	f.path = path
	return f.err
}

func (f *fakeSecret) List(ctx context.Context, principal authorization.Principal, prefix string) ([]string, error) {
	f.principal = principal
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
	principal authorization.Principal // the last principal any method got
	name      string                  // the last name Get or Delete got
	putPolicy authorization.Policy
	getPolicy authorization.Policy
	err       error
}

func (f *fakePolicy) Put(ctx context.Context, principal authorization.Principal, policy authorization.Policy) error {
	f.principal = principal
	f.putPolicy = policy
	return f.err
}

func (f *fakePolicy) Get(ctx context.Context, principal authorization.Principal, name string) (authorization.Policy, error) {
	f.principal = principal
	f.name = name
	return f.getPolicy, f.err
}

func (f *fakePolicy) Delete(ctx context.Context, principal authorization.Principal, name string) error {
	f.principal = principal
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
	principal authorization.Principal // the last principal any method got
	id        string                  // the last ID Get or Delete got
	created   identity.Entity
	createID  string
	getEntity identity.Entity
	updated   identity.Entity
	err       error
}

func (f *fakeEntity) CreateEntity(ctx context.Context, principal authorization.Principal, entity identity.Entity) (string, error) {
	f.principal = principal
	f.created = entity
	return f.createID, f.err
}

func (f *fakeEntity) GetEntity(ctx context.Context, principal authorization.Principal, id string) (identity.Entity, error) {
	f.principal = principal
	f.id = id
	return f.getEntity, f.err
}

func (f *fakeEntity) UpdateEntity(ctx context.Context, principal authorization.Principal, entity identity.Entity) error {
	f.principal = principal
	f.updated = entity
	return f.err
}

func (f *fakeEntity) DeleteEntity(ctx context.Context, principal authorization.Principal, id string) error {
	f.principal = principal
	f.id = id
	return f.err
}

type fakeToken struct {
	principal authorization.Principal
	entityID  string
	token     []byte
	err       error
}

func (f *fakeToken) CreateToken(ctx context.Context, principal authorization.Principal, entityID string) ([]byte, error) {
	f.principal = principal
	f.entityID = entityID
	return f.token, f.err
}

type tokenBody struct {
	Token string `json:"token"`
}

type groupBody struct {
	Policies []string `json:"policies"`
}

type createGroupBody struct {
	ID string `json:"id"`
}

type fakeGroup struct {
	principal authorization.Principal // the last principal any method got
	id        string                  // the last ID Get or Delete got
	created   identity.Group
	createID  string
	getGroup  identity.Group
	updated   identity.Group
	err       error
}

func (f *fakeGroup) CreateGroup(ctx context.Context, principal authorization.Principal, group identity.Group) (string, error) {
	f.principal = principal
	f.created = group
	return f.createID, f.err
}

func (f *fakeGroup) GetGroup(ctx context.Context, principal authorization.Principal, id string) (identity.Group, error) {
	f.principal = principal
	f.id = id
	return f.getGroup, f.err
}

func (f *fakeGroup) UpdateGroup(ctx context.Context, principal authorization.Principal, group identity.Group) error {
	f.principal = principal
	f.updated = group
	return f.err
}

func (f *fakeGroup) DeleteGroup(ctx context.Context, principal authorization.Principal, id string) error {
	f.principal = principal
	f.id = id
	return f.err
}

// bearer authenticates as whatever the router's authenticator decides; AQID is {1, 2, 3}.
const bearer = "Bearer AQID"

func do(t *testing.T, h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	return doWithAuthorization(t, h, bearer, method, path, body)
}

// doWithAuthorization sends authorization as the Authorization header, or none if it is empty.
func doWithAuthorization(t *testing.T, h http.Handler, authorization, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", contentTypeJSON)
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}

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
