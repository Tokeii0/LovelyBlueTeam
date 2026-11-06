package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAIPayloadRedactsNestedJSONAndQuery(t *testing.T) {
	e := makeEntry(`{"time":"2026-11-04T19:00:00+08:00","ip":"8.8.8.8","method":"POST","uri":"/api?token=query-secret&q=union+select","body":"{\"head\":{\"token\":\"head-secret\",\"app_id\":\"x' or 1=1--\"},\"body\":{\"patient_id\":\"private-patient\",\"phone\":\"private-phone\",\"query\":\"union select 1\"}}","status":"200"}`, nil)
	data, err := aiPayload([]Entry{e})
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"query-secret", "head-secret", "private-patient", "private-phone"} {
		if strings.Contains(string(data), secret) {
			t.Errorf("sensitive field leaked: %s", secret)
		}
	}
	if !strings.Contains(string(data), "union select 1") || !strings.Contains(string(data), "x' or 1=1--") {
		t.Fatal("redaction removed relevant attack context")
	}
	if len(e.Findings) == 0 {
		t.Fatal("local SQL signal not found")
	}
}

func TestTextAndXMLRedaction(t *testing.T) {
	for _, text := range []string{`password=hunter2&x=1`, `{"token":"abcdef"}`, `<token>abcdef</token>`, `<openid><![CDATA[abcdef]]></openid>`, `pass%77ord=hunter2&x=1`, `<auth_code><![CDATA[abcdef]]></auth_code>`} {
		result := redactText(text)
		if strings.Contains(result, "hunter2") || strings.Contains(result, "abcdef") {
			t.Fatal("plaintext field leaked")
		}
	}
	preview := redactedBody(`{"account_id":"13800138000","card_number":"000000000000000000","id_number":"123-secret","auth_code":"auth-private","query":"union select 1"}`)
	for _, secret := range []string{"13800138000", "000000000000000000", "123-secret", "auth-private"} {
		if strings.Contains(preview, secret) {
			t.Fatal("private identifier leaked")
		}
	}
	if !strings.Contains(preview, "union select 1") {
		t.Fatal("relevant query removed")
	}
}

func TestAIReceivesOnlyPreparedPayloadAndErrorsStayErrors(t *testing.T) {
	entry := Entry{ID: 5, Body: "RAW-CIPHERTEXT-SECRET", URI: "/a", Decoded: Decoded{State: "encrypted", Message: "missing key"}}
	var captured map[string]any
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer fixture-key" {
			t.Error("missing auth")
		}
		if err := json.NewDecoder(r.Body).Decode(&captured); err != nil {
			t.Error(err)
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"正文未解密，证据不足。"},"finish_reason":"stop"}]}`))
	}))
	defer upstream.Close()
	report, err := requestAnalysis(context.Background(), AIConfig{upstream.URL, "fixture-key", "test-model"}, []Entry{entry})
	if err != nil || !strings.Contains(report, "未解密") {
		t.Fatal("analysis request failed")
	}
	data, _ := json.Marshal(captured)
	if strings.Contains(string(data), entry.Body) {
		t.Fatal("opaque raw ciphertext leaked to model")
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(429)
		_, _ = w.Write([]byte("upstream-secret"))
	}))
	defer bad.Close()
	if _, err := requestAnalysis(context.Background(), AIConfig{bad.URL, "fixture-key", "test-model"}, []Entry{entry}); err == nil || strings.Contains(err.Error(), "upstream-secret") {
		t.Fatal("upstream error was accepted or exposed")
	}
}
