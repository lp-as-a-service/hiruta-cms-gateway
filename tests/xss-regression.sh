#!/bin/bash
# =============================================================
# XSS回帰テスト - hiruta-cms-gateway
#
# 使用方法:
#   ./tests/xss-regression.sh [GATEWAY_URL]
#
# 例:
#   ./tests/xss-regression.sh
#   ./tests/xss-regression.sh https://hiruta-cms-gateway.kazu12127823.workers.dev
# =============================================================

GATEWAY_URL="${1:-https://hiruta-cms-gateway.kazu12127823.workers.dev}"

PASS=0
FAIL=0
RESULTS=()

# -----------------------------------------------
# ヘルパー関数
# -----------------------------------------------
run_test() {
  local test_id="$1"
  local desc="$2"
  local url="$3"
  local method="${4:-GET}"
  local extra_args="${5:-}"

  if [ "$method" = "GET" ]; then
    body=$(curl -s -L --max-redirs 0 "$url" 2>/dev/null)
  else
    body=$(curl -s -L --max-redirs 0 -X POST $extra_args "$url" 2>/dev/null)
  fi

  # 生タグ（スクリプト実行可能な形）が含まれているか検出
  raw_script_count=$(echo "$body" | grep -c '<script>' 2>/dev/null)
  raw_script_count=$((raw_script_count + 0))
  # エスケープ済みの形が含まれているか検出
  escaped_count=$(echo "$body" | grep -c '&lt;script&gt;' 2>/dev/null)
  escaped_count=$((escaped_count + 0))

  if [ "$raw_script_count" -gt 0 ]; then
    FAIL=$((FAIL + 1))
    RESULTS+=("FAIL [$test_id] $desc")
    RESULTS+=("       生タグ検出数: $raw_script_count, エスケープ済み: $escaped_count")
    RESULTS+=("       URL: $url")
  elif [ "$escaped_count" -gt 0 ]; then
    PASS=$((PASS + 1))
    RESULTS+=("PASS [$test_id] $desc (エスケープ済み出力確認)")
  else
    # テキストが含まれるか確認（ページが正常に返っているか）
    if echo "$body" | grep -q 'Hiruta Studio\|href\|form\|input'; then
      # ページは返っているがXSSペイロードはどちらの形でも出現しない
      # → リダイレクトや別処理でXSSが到達していないケース（安全とみなす）
      PASS=$((PASS + 1))
      RESULTS+=("PASS [$test_id] $desc (XSSペイロード非出力 - 安全)")
    else
      FAIL=$((FAIL + 1))
      RESULTS+=("FAIL [$test_id] $desc (ページ取得失敗またはレスポンス異常)")
      RESULTS+=("       URL: $url")
    fi
  fi
}

# -----------------------------------------------
# テストケース実行
# -----------------------------------------------

echo "================================================================"
echo "XSS回帰テスト - hiruta-cms-gateway"
echo "対象: $GATEWAY_URL"
echo "================================================================"
echo ""

# T1: /auth の error パラメータ
run_test "T1" \
  "/auth?error=<script>alert(1)</script> → errorパラメータXSS" \
  "${GATEWAY_URL}/auth?error=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"

# T2: /auth/verify の email パラメータ（info表示箇所）
run_test "T2" \
  "/auth/verify?email=<script>alert(1)</script> → emailパラメータXSS" \
  "${GATEWAY_URL}/auth/verify?email=%3Cscript%3Ealert%281%29%3C%2Fscript%3E&t=dummy"

# T3: /auth/verify の error パラメータ
run_test "T3" \
  "/auth/verify?email=test@example.com&error=<script>alert(1)</script> → errorパラメータXSS" \
  "${GATEWAY_URL}/auth/verify?email=test%40example.com&error=%3Cscript%3Ealert%281%29%3C%2Fscript%3E&t=dummy"

# T4: /invite の token パラメータ
run_test "T4" \
  "/invite?t=<script>alert(1)</script> → tokenパラメータXSS" \
  "${GATEWAY_URL}/invite?t=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"

# T5: /auth/verify の resent=1 時の email パラメータ（再送信確認メッセージ）
run_test "T5" \
  "/auth/verify?email=<script>alert(1)</script>&resent=1 → resent表示でのemailパラメータXSS" \
  "${GATEWAY_URL}/auth/verify?email=%3Cscript%3Ealert%281%29%3C%2Fscript%3E&resent=1&t=dummy"

# T6: hiddenInputs のキー（k）にXSSペイロード
run_test "T6" \
  "/auth/verify?<script>alert(1)</script>=val → hidden input keyXSS" \
  "${GATEWAY_URL}/auth/verify?%3Cscript%3Ealert%281%29%3C%2Fscript%3E=val&email=test%40example.com&t=dummy"

# T7: hiddenInputs の値（v）にXSSペイロード
run_test "T7" \
  "/auth/verify?extra=<script>alert(1)</script> → hidden input valueXSS" \
  "${GATEWAY_URL}/auth/verify?extra=%3Cscript%3Ealert%281%29%3C%2Fscript%3E&email=test%40example.com&t=dummy"

# T8: /invite の error パラメータ（handleInviteGet はerrorパラメータを処理しないが念のため確認）
run_test "T8" \
  "/auth?email=<script>alert(1)</script> → auth formのemailフィールド確認" \
  "${GATEWAY_URL}/auth?email=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"

# -----------------------------------------------
# 結果出力
# -----------------------------------------------

echo ""
echo "================================================================"
echo "テスト結果"
echo "================================================================"
for r in "${RESULTS[@]}"; do
  echo "$r"
done
echo ""
echo "----------------------------------------------------------------"
echo "集計: PASS=${PASS} / FAIL=${FAIL} / TOTAL=$((PASS + FAIL))"
echo "----------------------------------------------------------------"

if [ "$FAIL" -gt 0 ]; then
  echo "FAILED: XSS脆弱性が検出されました。src/index.ts を確認してください。"
  exit 1
else
  echo "PASSED: 全テストケースでXSSは検出されませんでした。"
  exit 0
fi
