import time
import subprocess
import os
import cv2
import csv
import threading
import numpy as np
import ctypes, sys
import sqlite3
import json
from tkinter import filedialog, Tk, Toplevel, messagebox, Label, Button, Entry, Frame, END
from concurrent.futures import ThreadPoolExecutor
import queue
import re
import types
import uuid
import platform
import hashlib
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

# ========================================
# 管理者権限チェック
# ========================================
if not ctypes.windll.shell32.IsUserAnAdmin():
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, __file__, None, 1
    )
    sys.exit()

# グローバル制御変数
pause_event = threading.Event()
pause_event.set()

stop_event = threading.Event()

# ========================================
# 公開鍵
# ========================================
PUBLIC_KEY_PEM = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0qMoqP+KYYsdTg2z0qHX
EdWgYlQzQrsGxGgKjNsfOsT62Br9bFJps/spGdz62Fy1YFaUFG3W61+PtCdR5wuY
GNxdqPU/7t85SGNsS0GwgllxKma3midc2qfzb6+CKceK1S5fpVeAv+gSQugTia6Q
03a239rvnMEsms11HQMQlR53QHayAr0+2Li8uoub+nI+7sJ39yNyApRhCPwTfSeo
jk3aZkoWrGqIrFGgKZUeiHG44L9XLg5WN0j3DK4JBupvPTgrtTFStfLXuTVqSRsg
924pzS2i/5GRWPCJHcGFm1aYSUibvv1JqAm/XM1RlT6L9hNT0iTB3mLAXXDSSRMw
IQIDAQAB
-----END PUBLIC KEY-----"""

# ========================================
# ライセンス認証関数
# ========================================
def get_hwid():
    try:
        mac = uuid.getnode()
        hostname = platform.node()
        raw_string = f"{mac}_{hostname}"
        hwid = hashlib.sha256(raw_string.encode()).hexdigest()
        return hwid
    except Exception as e:
        return hashlib.sha256(b"fallback_hwid").hexdigest()

def private_key_matches_public(private_path="private.pem"):
    if not os.path.exists(private_path):
        return False
    try:
        with open(private_path, "rb") as f:
            private_bytes = f.read()
        private_key = serialization.load_pem_private_key(private_bytes, password=None)
        pub_from_priv = private_key.public_key()
        pub_pem_from_priv = pub_from_priv.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")
        normalized_existing = "".join(PUBLIC_KEY_PEM.split())
        normalized_new = "".join(pub_pem_from_priv.split())
        return normalized_existing == normalized_new
    except Exception:
        return False

def load_public_key():
    try:
        public_key = serialization.load_pem_public_key(PUBLIC_KEY_PEM.encode('utf-8'))
        return public_key
    except Exception as e:
        raise Exception(f"公開鍵の読み込みに失敗しました: {e}")

def load_license_file(license_path="license.lic"):
    if not os.path.exists(license_path):
        return None
    try:
        with open(license_path, "r", encoding="utf-8") as f:
            content = f.read().strip()
            if not content:
                return None
            return content
    except Exception:
        return None

def verify_license_token(token, hwid):
    try:
        parts = token.split(".")
        if len(parts) != 2:
            return False, "無効なライセンス形式です", 0
        
        payload_b64, signature_b64 = parts
        
        try:
            payload_bytes = base64.urlsafe_b64decode(payload_b64.encode('ascii'))
            signature_bytes = base64.urlsafe_b64decode(signature_b64.encode('ascii'))
        except Exception:
            return False, "ライセンスのデコードに失敗しました", 0
        
        public_key = load_public_key()
        
        try:
            public_key.verify(signature_bytes, payload_bytes, padding.PKCS1v15(), hashes.SHA256())
        except InvalidSignature:
            return False, "署名検証失敗（ライセンスが改ざんされています）", 0
        except Exception as e:
            return False, f"署名検証エラー: {str(e)}", 0
        
        try:
            payload = json.loads(payload_bytes.decode('utf-8'))
        except json.JSONDecodeError:
            return False, "ライセンスデータが破損しています", 0
        
        if payload.get("hwid") != hwid:
            return False, "このPCでは使用できません（HWID不一致）", 0
        
        now = int(time.time())
        expires_at = payload.get("expires_at", 0)
        
        if expires_at < now:
            expired_date = time.strftime('%Y-%m-%d', time.localtime(expires_at))
            return False, f"ライセンスの有効期限が切れています（期限: {expired_date}）", 0
        
        days_left = (expires_at - now) / (24 * 3600)
        return True, "ライセンス有効", int(days_left)
        
    except Exception as e:
        return False, f"検証中にエラーが発生しました: {str(e)}", 0

def check_license_gui():
    if private_key_matches_public("private.pem"):
        root = Tk()
        root.withdraw()
        messagebox.showinfo(
            "ライセンス認証（スキップ）",
            "private.pem が見つかり、公開鍵が一致したためライセンスチェックをスキップします。"
        )
        root.destroy()
        return True

    hwid = get_hwid()
    token = load_license_file("license.lic")

    if token is None:
        root = Tk()
        root.withdraw()
        msg = (
            f"ライセンスファイル (license.lic) が見つかりません\n\n"
            f"あなたのハードウェアID:\n{hwid}\n\n"
            f"このIDを開発者に送付してライセンスを取得してください。"
        )
        messagebox.showerror("ライセンスエラー", msg)
        root.destroy()
        return False

    success, message, days_left = verify_license_token(token, hwid)

    if success:
        root = Tk()
        root.withdraw()
        if days_left <= 7:
            messagebox.showwarning(
                "ライセンス警告",
                f"{message}\n有効期限まで残り: {days_left}日\n\n警告: 有効期限が近づいています"
            )
        else:
            messagebox.showinfo("ライセンス認証", f"{message}\n有効期限まで残り: {days_left}日")
        root.destroy()
        return True
    else:
        root = Tk()
        root.withdraw()
        messagebox.showerror("認証失敗", f"{message}\n\nあなたのHWID:\n{hwid}")
        root.destroy()
        return False

if not check_license_gui():
    sys.exit(1)

# ========================================
# 既存の関数群
# ========================================
def decode_bytes(b: bytes) -> str:
    if b is None:
        return ""
    if isinstance(b, str):
        return b
    try:
        return b.decode("utf-8")
    except UnicodeDecodeError:
        return b.decode("cp932", errors="replace")

def run_cmd_capture_output(cmd, timeout=None):
    completed = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    out = decode_bytes(completed.stdout)
    if completed.returncode != 0:
        err = decode_bytes(completed.stderr)
        raise subprocess.CalledProcessError(completed.returncode, cmd, output=out, stderr=err)
    return out

def log(message, device_id=None):
    if device_id:
        print(f"[{device_id}] {message}")
    else:
        print(f"[SYSTEM] {message}")

# -------------------------------
# SQLite関連
# -------------------------------
class EmailManager:
    def __init__(self, csv_path):
        self.db_path = "emails.db"
        self.csv_path = csv_path
        self.lock = threading.Lock()
        self._init_db(csv_path)
    
    def _init_db(self, csv_path):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS emails (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE,
                    used INTEGER DEFAULT 0
                )
            ''')
            
            if os.path.exists(csv_path):
                try:
                    with open(csv_path, "r", encoding="utf-8") as f:
                        lines = [l.strip() for l in f if l.strip()]
                    
                    for email in lines:
                        try:
                            conn.execute('INSERT OR IGNORE INTO emails (email) VALUES (?)', (email,))
                        except sqlite3.Error as e:
                            log(f"メール挿入エラー {email}: {e}")
                    
                    conn.commit()
                    log(f"CSVから {len(lines)} 件のメールをインポート完了")
                except Exception as e:
                    log(f"CSV読み込みエラー: {e}")
    
    def pop_email(self):
        with self.lock:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    'SELECT id, email FROM emails WHERE used = 0 ORDER BY id LIMIT 1'
                )
                row = cursor.fetchone()
                
                if row is None:
                    raise Exception("利用可能なメールがありません")
                
                email_id, email = row
                conn.execute('UPDATE emails SET used = 1 WHERE id = ?', (email_id,))
                conn.commit()
                
                return email
    
    def get_remaining_count(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute('SELECT COUNT(*) FROM emails WHERE used = 0')
            return cursor.fetchone()[0]
    
    def clean_csv_file(self):
        with self.lock:
            try:
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.execute('SELECT email FROM emails WHERE used = 1')
                    used_emails = {row[0] for row in cursor.fetchall()}
                
                if not used_emails:
                    log("削除対象のメールはありません")
                    return
                
                with open(self.csv_path, "r", encoding="utf-8") as f:
                    lines = [l.strip() for l in f if l.strip()]
                
                remaining = [email for email in lines if email not in used_emails]
                
                with open(self.csv_path, "w", encoding="utf-8") as f:
                    for email in remaining:
                        f.write(f"{email}\n")
                
                log(f"CSVクリーン完了: {len(used_emails)}件削除、{len(remaining)}件残存")
            except Exception as e:
                log(f"CSVクリーンエラー: {e}")

# -------------------------------
# デバイス・LDPlayerマッピング
# -------------------------------
def get_device_ldplayer_mapping():
    adb_path = None
    ldplayer_path = r"C:\LDPlayer\LDPlayer9\dnconsole.exe"
    
    root = Tk()
    root.withdraw()
    adb_path = filedialog.askopenfilename(
        title="Select adb.exe",
        filetypes=[("ADB Executable", "adb.exe")]
    )
    if not adb_path:
        log("adb.exe が選択されませんでした")
        return None, {}
    
    try:
        adb_out = run_cmd_capture_output([adb_path, "devices"], timeout=5)
        lines = adb_out.strip().split("\n")[1:]
        adb_devices = [line.split()[0] for line in lines if "device" in line and "emulator-" in line]
        log(f"ADB検出端末: {adb_devices}")
    except Exception as e:
        log(f"adb devices取得エラー: {e}")
        return adb_path, {}
    
    try:
        list2_out = run_cmd_capture_output([ldplayer_path, "list2"], timeout=5)
        ld_basic_info = {}

        log("LDPlayer list2 出力:")
        for line in list2_out.strip().split("\n"):
            log(f"  {line}")
            parts = line.split(",")
            if len(parts) >= 2:
                try:
                    index = int(parts[0])
                    name = parts[1]
                    ld_basic_info[index] = name
                except (ValueError, IndexError):
                    continue
        log(f"LDPlayer基本情報取得完了: {len(ld_basic_info)}個のインスタンス")
    except Exception as e:
        log(f"dnconsole list2取得エラー: {e}")
        return adb_path, {}
    
    try:
        running_out = run_cmd_capture_output([ldplayer_path, "runninglist"], timeout=5)
        running_names = []

        log("LDPlayer runninglist 出力:")
        for line in running_out.strip().split("\n"):
            line = line.strip()
            if line:
                log(f"  {line}")
                running_names.append(line)
        log(f"起動中LDPlayer名: {running_names}")
    except Exception as e:
        log(f"dnconsole runninglist取得エラー: {e}")
        return adb_path, {}
    
    running_indices = []
    for name in running_names:
        for index, basic_name in ld_basic_info.items():
            if basic_name == name:
                running_indices.append(index)
                log(f"起動中インスタンス特定: {name} → index {index}")
                break
        else:
            log(f"警告: 起動中インスタンス '{name}' に対応するindexが見つかりません")
    
    ld_instances_with_port = {}
    log("各インスタンスのADBシリアル番号を個別取得中...")
    
    for index in running_indices:
        try:
            log(f"index {index} のADBシリアル番号取得中...", f"LD-{index}")

            raw_output = run_cmd_capture_output(
                [ldplayer_path, "adb", "--index", str(index), "--command", "get-serialno"],
                timeout=10
            ).strip()
            log(f"get-serialno 生出力: '{raw_output}'", f"LD-{index}")

            match = re.search(r'emulator-(\d+)', raw_output)
            if match:
                port_num = int(match.group(1))
                emulator_id = f"emulator-{port_num}"
                instance_name = ld_basic_info.get(index, f"Unknown-{index}")

                ld_instances_with_port[emulator_id] = {
                    'index': index,
                    'name': instance_name,
                    'port': port_num
                }
                log(
                    f"ADBシリアル番号取得成功: index={index}, name={instance_name}, serial={emulator_id}",
                    f"LD-{index}"
                )
            else:
                log(f"ADBシリアル番号抽出失敗: 出力に 'emulator-XXXX' が見つかりません", f"LD-{index}")

        except subprocess.TimeoutExpired:
            log(f"ADBシリアル番号取得タイムアウト (10秒)", f"LD-{index}")
            continue
        except subprocess.CalledProcessError as e:
            log(f"get-serialno コマンドエラー: {e}", f"LD-{index}")
            continue
        except Exception as e:
            log(f"予期しないエラー: {e}", f"LD-{index}")
            continue

    log(f"ADBシリアル番号取得完了: {len(ld_instances_with_port)}個のインスタンス")
    
    mapping = {}
    for adb_device in adb_devices:
        if adb_device in ld_instances_with_port:
            ld_info = ld_instances_with_port[adb_device]
            mapping[adb_device] = ld_info['index']
            log(f"マッピング成功: {adb_device} → LDPlayer index {ld_info['index']} ({ld_info['name']})")
        else:
            log(f"マッピング失敗: {adb_device} に対応するLDPlayerが見つかりません")
    
    if not mapping:
        log("有効なマッピングが見つかりませんでした")
    else:
        log(f"最終マッピング結果: {mapping}")
    
    return adb_path, mapping

# -------------------------------
# ADB関連
# -------------------------------
def run_adb(adb_path, device_id, *args, timeout=15):
    cmd = [adb_path, "-s", device_id] + list(args)
    log(f"実行: {' '.join(cmd)}", device_id)
    try:
        completed = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        if completed.returncode != 0:
            stderr_text = decode_bytes(completed.stderr)
            log(f"ADBコマンドエラー (rc={completed.returncode}): {stderr_text}", device_id)
            raise subprocess.CalledProcessError(completed.returncode, cmd, output=completed.stdout, stderr=completed.stderr)
        out = decode_bytes(completed.stdout)
        return types.SimpleNamespace(stdout=out)
    except subprocess.CalledProcessError as e:
        raise
    except Exception as e:
        log(f"ADBコマンド例外: {e}", device_id)
        raise

def tap(adb_path, device_id, x, y, delay=0.0):
    run_adb(adb_path, device_id, "shell", "input", "tap", str(int(x)), str(int(y)))
    if delay > 0:
        time.sleep(delay)

def text(adb_path, device_id, input_text, delay=0.0):
    run_adb(adb_path, device_id, "shell", "input", "text", input_text)
    if delay > 0:
        time.sleep(delay)

def swipe(adb_path, device_id, x1, y1, x2, y2, duration=300, delay=0.0):
    run_adb(adb_path, device_id, "shell", "input", "swipe",
            str(int(x1)), str(int(y1)), str(int(x2)), str(int(y2)), str(int(duration)))
    if delay > 0:
        time.sleep(delay)

def wait(sec):
    time.sleep(sec)

def check_boot_completed(adb_path, device_id):
    try:
        result = run_adb(adb_path, device_id, "shell", "getprop", "sys.boot_completed")
        return result.stdout.strip() == "1"
    except:
        return False

# -------------------------------
# LDPlayer再起動関連
# -------------------------------
def wait_for_process_exit(process_name, timeout=30):
    for _ in range(timeout):
        try:
            out = run_cmd_capture_output(["tasklist", "/FI", f"IMAGENAME eq {process_name}", "/FO", "CSV"], timeout=5)
            if process_name not in out:
                return True
        except subprocess.CalledProcessError:
            pass
        except Exception:
            pass
        time.sleep(1)
    return False

def restart_ldplayer_safe(adb_path, device_id, ld_index):
    ldplayer_path = r"C:\LDPlayer\LDPlayer9\dnconsole.exe"
    
    if not os.path.exists(ldplayer_path):
        log(f"dnconsole.exe が見つかりません: {ldplayer_path}", device_id)
        return False
    
    log(f"LDPlayer index {ld_index} を安全に再起動開始", device_id)
    
    try:
        subprocess.run([ldplayer_path, "quit", "--index", str(ld_index)], check=True, timeout=10)
        log("終了コマンド送信完了", device_id)
    except Exception as e:
        log(f"終了コマンドエラー: {e}", device_id)
        return False
    
    log("プロセス終了待機中...", device_id)
    if not wait_for_process_exit("LDVBoxHeadless.exe", timeout=30):
        log("プロセス終了タイムアウト", device_id)
        return False
    
    time.sleep(2)
    
    try:
        subprocess.run([ldplayer_path, "launch", "--index", str(ld_index)], check=True, timeout=10)
        log("起動コマンド送信完了", device_id)
    except Exception as e:
        log(f"起動コマンドエラー: {e}", device_id)
        return False
    
    log("起動完了待機中...", device_id)
    max_wait = 60
    for i in range(max_wait):
        try:
            if check_boot_completed(adb_path, device_id):
                log(f"起動完了確認 ({i}秒)", device_id)
                time.sleep(5)
                return True
        except:
            pass
        
        if i % 10 == 0:
            log(f"起動待機中... ({i}/{max_wait}秒)", device_id)
        time.sleep(1)
    
    log("起動完了タイムアウト", device_id)
    return False

# -------------------------------
# 画像認識関連（拡張版）
# -------------------------------
def get_screenshot(adb_path, device_id):
    try:
        result = subprocess.run(
            [adb_path, "-s", device_id, "exec-out", "screencap", "-p"],
            stdout=subprocess.PIPE, check=True, timeout=10
        )
        image_bytes = np.frombuffer(result.stdout, np.uint8)
        screen = cv2.imdecode(image_bytes, cv2.IMREAD_COLOR)
        return screen
    except Exception as e:
        log(f"スクリーンショット取得エラー: {e}", device_id)
        return None

def find_template(screen, template_path, threshold=0.8):
    template = cv2.imread(template_path)
    if template is None:
        return None, 0.0, None
    
    h, w = template.shape[:2]
    res = cv2.matchTemplate(screen, template, cv2.TM_CCOEFF_NORMED)
    _, max_val, _, max_loc = cv2.minMaxLoc(res)
    
    if max_val >= threshold:
        x = max_loc[0] + w // 2
        y = max_loc[1] + h // 2
        return (x, y), max_val, (w, h)
    
    return None, max_val, (w, h)

def tap_image_extended(adb_path, device_id, ld_index, template_path, threshold=0.8, retries=12, restart_on_fail=True, previous_action=None):
    """
    拡張版画像認識タップ
    previous_action: 4回失敗するたびに実行する前ステップのアクション（関数）
    """
    log(f"画像認識開始: {template_path}", device_id)
    max_val = 0
    retry_with_previous = 0
    
    for attempt in range(1, retries + 1):
        try:
            screen = get_screenshot(adb_path, device_id)
            if screen is None:
                log(f"スクショ失敗 {attempt}/{retries}", device_id)
                time.sleep(1)
                continue
            
            position, max_val, size = find_template(screen, template_path, threshold)
            
            if position:
                x, y = position
                tap(adb_path, device_id, x, y)
                log(f"画像認識成功 {attempt}/{retries}: {template_path} → ({x},{y}) 類似度{max_val:.3f}", device_id)
                return True, False
            
            log(f"画像未検出 {attempt}/{retries}: {template_path} (類似度{max_val:.3f})", device_id)
            
            # 修正: 4回失敗するたびに前ステップを実行
            if previous_action and attempt % 4 == 0 and attempt < retries:
                retry_with_previous += 1
                log(f"4回失敗 → 前ステップを実行します（{retry_with_previous}回目）", device_id)
                try:
                    previous_action()
                    wait(1.0)  # 前ステップ実行後の待機
                except Exception as e:
                    log(f"前ステップ実行エラー: {e}", device_id)
            
            time.sleep(1)
            
        except Exception as e:
            log(f"画像認識例外 {attempt}/{retries}: {e}", device_id)
            time.sleep(1)
    
    if restart_on_fail:
        log(f"画像認識失敗: {template_path} (最終類似度{max_val:.3f}) → 再起動実行", device_id)
        restart_success = restart_ldplayer_safe(adb_path, device_id, ld_index)
        return False, restart_success
    else:
        log(f"画像認識失敗: {template_path} (最終類似度{max_val:.3f}) → 再起動しません", device_id)
        return False, False
    
def uisupa(adb_path, device_id, x, y, times=8, interval=0.4):
    for _ in range(times):
        if not check_control_events(device_id):
            return False
        tap(adb_path, device_id, x, y)
        wait(interval)
    return True


# 個別の画像認識関数群（前ステップアクション付き）
def tap_punipuni(adb_path, device_id, ld_index, restart_on_fail=True):
    return tap_image_extended(adb_path, device_id, ld_index, "img/punipuni.png", 
                            threshold=0.8, retries=12, restart_on_fail=restart_on_fail)

def tap_agree_button(adb_path, device_id, ld_index, restart_on_fail=True, previous_action=None):
    """同意ボタン - 4回失敗ごとに前ステップ実行"""
    return tap_image_extended(adb_path, device_id, ld_index, "img/agree_button.png", 
                            threshold=0.8, retries=12, restart_on_fail=restart_on_fail,
                            previous_action=previous_action)

def tap_ok_button(adb_path, device_id, ld_index, restart_on_fail=True, previous_action=None):
    """次へボタン - 4回失敗ごとに前ステップ実行"""
    return tap_image_extended(adb_path, device_id, ld_index, "img/ok_button.png", 
                            threshold=0.8, retries=12, restart_on_fail=restart_on_fail,
                            previous_action=previous_action)

def tap_data_button(adb_path, device_id, ld_index, restart_on_fail=True, previous_action=None):
    """データボタン - 4回失敗ごとに前ステップ実行"""
    return tap_image_extended(adb_path, device_id, ld_index, "img/data_button.png", 
                            threshold=0.8, retries=12, restart_on_fail=restart_on_fail,
                            previous_action=previous_action)

def tap_email_field(adb_path, device_id, ld_index, restart_on_fail=True):
    return tap_image_extended(adb_path, device_id, ld_index, "img/email_field.png", 
                            threshold=0.9, retries=12, restart_on_fail=restart_on_fail)

def tap_login_button(adb_path, device_id, ld_index, restart_on_fail=True):
    return tap_image_extended(adb_path, device_id, ld_index, "img/login_button.png", 
                            threshold=0.8, retries=12, restart_on_fail=restart_on_fail)

def tap_play_button(adb_path, device_id, ld_index, restart_on_fail=True):
    return tap_image_extended(adb_path, device_id, ld_index, "img/play_button.png", 
                            threshold=0.8, retries=12, restart_on_fail=restart_on_fail)

def tap_next_button(adb_path, device_id, ld_index, restart_on_fail=True):
    return tap_image_extended(adb_path, device_id, ld_index, "img/next_button.png", 
                            threshold=0.8, retries=12, restart_on_fail=restart_on_fail)

def wait_for_image(adb_path, device_id, ld_index, image_path, threshold=0.8, timeout=30):
    """
    指定した画像が見えるまで待機する。
    見つかったら True、タイムアウトしたら False を返す。
    """
    start_time = time.time()
    while True:
        if not check_control_events(device_id):
            return False

        # 画像認識して、見つかったら True
        success, _ = tap_image_extended(
            adb_path, device_id, ld_index,
            image_path,
            threshold=threshold,
            retries=1,             # ここでは1回だけ確認
            restart_on_fail=False
        )

        if success:
            return True

        # タイムアウト処理
        if time.time() - start_time > timeout:
            print(f"[{device_id}] 画像 {image_path} が見つからずタイムアウト")
            return False

        wait(0.5)

def tap_image(adb_path, device_id, ld_index, template_path, threshold=0.8, retries=12):
    return tap_image_extended(adb_path, device_id, ld_index, template_path, threshold, retries, True)

def check_control_events(device_id):
    if stop_event.is_set():
        log("停止シグナル検出、マクロを中断", device_id)
        return False
    
    if not pause_event.is_set():
        log("一時停止中...", device_id)
        pause_event.wait()
        log("一時停止解除、マクロ再開", device_id)
    
    return True

# マクロ本体（画像認識版・前ステップアクション対応）
def run_macro(adb_path, device_id, ld_index, mail, password, is_group1=False):
    """メインマクロ処理（画像認識版）- 一時停止・停止・前ステップ戻り対応"""
    max_restarts = 3
    
    for restart_count in range(max_restarts + 1):
        try:
            if restart_count > 0:
                log(f"再起動後のマクロ再実行 ({restart_count}/{max_restarts})", device_id)
            else:
                log(f"マクロ開始: {mail}", device_id)

            if not check_control_events(device_id):
                return False

            # ステップ1: punipuni
            success, restarted = tap_punipuni(adb_path, device_id, ld_index)
            if not success:
                if restarted:
                    continue
                else:
                    return False
            wait(5)
            
            if not check_control_events(device_id):
                return False
            
            # ステップ2: ok_btm
            success, restarted = tap_image(adb_path, device_id, ld_index, "img/ok_btm.png", threshold=0.8, retries=45)
            if not success:
                if restarted:
                    return False
                else:
                    return False
            
            wait(2.5)
            
            if not check_control_events(device_id):
                return False
            
            # ステップ3: 座標タップ (310, 846.7)
            tap(adb_path, device_id, 310, 846.7)
            wait(0.5)
            
            if not check_control_events(device_id):
                return False
            
            # ステップ4: 登録ボタン（前ステップ: 座標タップ）
            def previous_step_for_register():
                tap(adb_path, device_id, 310, 846.7)

            success, restarted = tap_agree_button(adb_path, device_id, ld_index,
                                                    previous_action=previous_step_for_register)
            if not success:
                if restarted:
                    continue
                else:
                    return False
            
            wait(1.0)
            
            if not check_control_events(device_id):
                return False
            
            # ステップ5: 次へボタン（前ステップ: 登録ボタン）
            def previous_step_for_next():
                # 登録ボタンを再度タップ（画像認識なしで座標のみ）
                # または登録ボタンの画像認識を再実行したい場合は以下を使用
                tap(adb_path, device_id, 622.9, 1167.6)  # 登録ボタンの座標

            success, restarted = tap_ok_button(adb_path, device_id, ld_index,
                                                previous_action=previous_step_for_next)
            if not success:
                if restarted:
                    continue
                else:
                    return False
            
            wait(1.0)
            
            if not check_control_events(device_id):
                return False
            
            # ステップ6: 同意ボタン（前ステップ: 次へボタン）
            def previous_step_for_agree():
                tap(adb_path, device_id, 460.6, 1347.9)  # 次へボタンの座標

            success, restarted = tap_data_button(adb_path, device_id, ld_index,
                                                previous_action=previous_step_for_agree)
            if not success:
                if restarted:
                    continue
                else:
                    return False
            
            wait(0.5)
            
            if not check_control_events(device_id):
                return False
            
            # ステップ7: メールアドレス入力欄
            success, restarted = tap_email_field(adb_path, device_id, ld_index)
            if not success:
                if restarted:
                    continue
                else:
                    return False
            
            wait(0.5)
            
            if not check_control_events(device_id):
                return False
            
            text(adb_path, device_id, mail)
            wait(0.5)
            
            if not check_control_events(device_id):
                return False
            
            tap(adb_path, device_id, 298.2, 879.5)
            wait(0.5)
            
            if not check_control_events(device_id):
                return False
            
            text(adb_path, device_id, password)
            tap(adb_path, device_id, 393.3, 1023.5)
            wait(0.7)
            
            if not check_control_events(device_id):
                return False
            
            # ステップ8: ログインボタン
            success, restarted = tap_login_button(adb_path, device_id, ld_index)
            if not success:
                if restarted:
                    continue
                else:
                    return False
            wait(2.0)
            
            if not check_control_events(device_id):
                return False
            
            # ステップ9: 残りの処理（座標指定）
            tap(adb_path, device_id, 434.3, 1293.8)
            tap(adb_path, device_id, 434.3, 1293.8)
            wait(0.1)
            
            if not check_control_events(device_id):
                return False
            
            # スワイプ処理
            swipe(adb_path, device_id, 462.2, 782.9, 490.1, 1320.0)
            swipe(adb_path, device_id, 490.1, 1320.0, 462.2, 782.9)
            swipe(adb_path, device_id, 462.2, 782.9, 490.1, 1320.0)
            swipe(adb_path, device_id, 490.1, 1320.0, 462.2, 782.9)
            swipe(adb_path, device_id, 462.2, 782.9, 490.1, 1320.0)
            swipe(adb_path, device_id, 490.1, 1320.0, 462.2, 782.9)
            swipe(adb_path, device_id, 462.2, 782.9, 490.1, 1320.0)
            swipe(adb_path, device_id, 462.2, 782.9, 490.1, 1320.0)
            swipe(adb_path, device_id, 490.1, 1320.0, 462.2, 782.9)
            swipe(adb_path, device_id, 462.2, 782.9, 490.1, 1320.0)
            swipe(adb_path, device_id, 490.1, 1320.0, 462.2, 782.9)
            swipe(adb_path, device_id, 462.2, 782.9, 490.1, 1320.0)
            swipe(adb_path, device_id, 490.1, 1320.0, 462.2, 782.9)
            swipe(adb_path, device_id, 462.2, 782.9, 490.1, 1320.0)            
            wait(0)
            
            if not check_control_events(device_id):
                return False
            
            # 連続タップ
            for _ in range(4):
                tap(adb_path, device_id, 259.0, 1039.9)
                wait(0.1)
            wait(0.7)
            
            if not check_control_events(device_id):
                return False
            
            tap(adb_path, device_id, 265.5, 791.0)
            wait(1.0)
            
            if not check_control_events(device_id):
                return False
            
            tap(adb_path, device_id, 410.7, 686.7)
            wait(0.9)
            
            if not check_control_events(device_id):
                return False
            
            text(adb_path, device_id, "@C17143")
            wait(1.0)
            
            if not check_control_events(device_id):
                return False
            
            tap(adb_path, device_id, 427.7, 938.4)
            wait(0.7)
            
            if not check_control_events(device_id):
                return False
            
            tap(adb_path, device_id, 652.4, 936.7)
            wait(0.7)
            
            for _ in range(3):
                if not check_control_events(device_id):
                    return False
                tap(adb_path, device_id, 652.4, 936.7)
                wait(0.4)
            wait(0.5)
            
            if not check_control_events(device_id):
                return False
            
            tap(adb_path, device_id, 445.8, 1223.4)
            for _ in range(5):
                if not check_control_events(device_id):
                    return False
                tap(adb_path, device_id, 445.8, 1223.4)
                wait(0.1)
            wait(1.0)
            
            for _ in range(15):
                if not check_control_events(device_id):
                    return False
                tap(adb_path, device_id, 445.8, 1223.4)
                wait(0.1)
            wait(0.3)
            
            if not check_control_events(device_id):
                return False
            #アカウント連携までがここ
            #通常ステージ処理
            tap(adb_path, device_id, 45.9, 173.6)
            wait(0.7)
            if not check_control_events(device_id):
                return False
            
            tap(adb_path, device_id, 37,372)
            if not check_control_events(device_id):
                    return False
            wait(0.3)
            tap (adb_path, device_id, 338,1133)
            if not check_control_events(device_id):
                    return False
            wait(0.5)
            tap (adb_path, device_id, 250,930)
            if not check_control_events(device_id):
                    return False
            wait(2.0)
            uisupa(adb_path, device_id, 463, 1216, times=10, interval=0.4)
            wait(0.7)
            tap (adb_path, device_id, 263,918)
            if not check_control_events(device_id):
                    return False
            wait(1.5)
            tap (adb_path, device_id, 600,1167)
            if not check_control_events(device_id):
                    return False
            if not wait_for_image(adb_path, device_id, ld_index, "img/uisupa.png", threshold=0.8, timeout=30):
                return False
            uisupa(adb_path, device_id, 260, 1216, times=8, interval=0.4)
            wait(0.5)
            while True:
                if not check_control_events(device_id):
                    return False
                success, restarted = tap_play_button(adb_path, device_id, ld_index)

                if success:
                    break
                
                if restarted:
                    continue

                tap(adb_path, device_id, 600, 925)
                wait(0.4)
            if not wait_for_image(adb_path, device_id, ld_index, "img/uisupa.png", threshold=0.8, timeout=30):
                return False
            uisupa(adb_path, device_id, 260, 1216, times=8, interval=0.4)
            wait(0.5)
            uisupa(adb_path, device_id, 508, 917, times=12, interval=0.3)
            wait(3.0)
            success, restarted = tap_next_button(adb_path, device_id, ld_index)
            if not success:
                if restarted:
                    continue
                else:
                    return False
            wait(4.0)
            tap(adb_path, device_id, 777, 777)
            wait(0.8)
            success, restarted = tap_play_button(adb_path, device_id, ld_index)
            if not success:
                if restarted:
                    continue
                else:
                    return False
            if not wait_for_image(adb_path, device_id, ld_index, "img/uisupa.png", threshold=0.8, timeout=30):
                return False
            uisupa(adb_path, device_id, 260, 1216, times=8, interval=0.4)
            uisupa(adb_path, device_id, 508, 917, times=15, interval=0.4)
            success, restarted = tap_next_button(adb_path, device_id, ld_index)
            if not success:
                if restarted:
                    continue
                else:
                    return 
            じばにゃんの前までできた
            


            #MOD
            tap(adb_path, device_id, 45.9, 173.6)
            wait(0.7)
            
            if not check_control_events(device_id):
                return False
            
            tap(adb_path, device_id, 180, 970)
            wait(0.5)
            
            if not check_control_events(device_id):
                return False
            
            tap(adb_path, device_id, 223, 830)
            wait(0.5)
            
            if not check_control_events(device_id):
                return False
            
            tap(adb_path, device_id, 790, 913)
            
            log("マクロ完了", device_id)
            return True
                
        except Exception as e:
            log(f"マクロ実行中エラー（再起動しません）: {e}", device_id)
            return False
    
    log(f"最大再起動回数({max_restarts})に達しました", device_id)
    return False

def device_worker(adb_path, device_id, ld_index, email_manager,
                  count, output_path, fixed_password,
                  instance_index, total_instances,
                  group):
    """各端末の独立処理（グループ単位で待機時間付き）"""
    log(f"ワーカー開始 (LDPlayer index {ld_index}, group {group})", device_id)
    success_count = 0

    group_index = group - 1 
    if group_index > 0:
        start_delay = group_index * 14
        log(f"グループ{group}は開始まで{start_delay}秒待機します", device_id)
        time.sleep(start_delay)

    for i in range(success_count, count):
        pause_event.wait()
        if stop_event.is_set():
            log(f"停止シグナル検出、処理を中断します", device_id)
            break

        try:
            mail = email_manager.pop_email()
            remaining = email_manager.get_remaining_count()
            log(f"処理 {i+1}/{count}: {mail} (残り{remaining}件)", device_id)

            success = run_macro(
                adb_path, device_id, ld_index, mail, fixed_password,
                is_group1=(group == 1)
            )

            if success:
                with open(output_path, "a", encoding="utf-8") as f:
                    f.write(f"{mail}:{fixed_password}\n")
                success_count += 1
                log(f"処理成功 ({success_count}/{i+1})", device_id)
                time.sleep(2)
            else:
                log(f"処理失敗: {mail}", device_id)

        except Exception as e:
            log(f"予期しないエラー: {e}", device_id)
            continue

    log(f"ワーカー完了 成功: {success_count}/{count}", device_id)

    return success_count

def kill_all_ldplayers():
    try:
        log("LDPlayerプロセスを終了中...")
        subprocess.run(["taskkill", "/F", "/IM", "dnplayer.exe"], 
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["taskkill", "/F", "/IM", "LDVBoxHeadless.exe"], 
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["taskkill", "/F", "/IM", "adb.exe"], 
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        log("LDPlayerプロセス終了完了")
    except Exception as e:
        log(f"LDPlayerプロセス終了エラー: {e}")

class ControlPanel:
    def __init__(self, total_count, total_devices):
        self.window = Toplevel()
        self.window.title("処理制御パネル")
        self.window.geometry("400x300")
        self.window.protocol("WM_DELETE_WINDOW", self.on_close)
        
        self.is_paused = False
        self.total_count = total_count
        self.total_devices = total_devices
        
        Label(self.window, text="処理制御パネル", 
              font=("Arial", 16, "bold")).pack(pady=20)
        
        self.status_label = Label(self.window, text="処理中...", 
                                 font=("Arial", 12), fg="green")
        self.status_label.pack(pady=10)
        
        info_frame = Frame(self.window)
        info_frame.pack(pady=10)
        
        Label(info_frame, text=f"検出端末数: {total_devices}台", 
              font=("Arial", 10)).pack()
        Label(info_frame, text=f"各端末の作成件数: {total_count}件", 
              font=("Arial", 10)).pack()
        Label(info_frame, text=f"合計予定件数: {total_count * total_devices}件", 
              font=("Arial", 10)).pack()
        
        btn_frame = Frame(self.window)
        btn_frame.pack(pady=20)
        
        self.pause_btn = Button(btn_frame, text="一時停止", 
                               command=self.toggle_pause,
                               font=("Arial", 11), bg="#FFA500", fg="white",
                               width=12, height=2)
        self.pause_btn.pack(side="left", padx=10)
        
        self.stop_btn = Button(btn_frame, text="強制終了", 
                              command=self.force_stop,
                              font=("Arial", 11), bg="#FF0000", fg="white",
                              width=12, height=2)
        self.stop_btn.pack(side="left", padx=10)
        
    def toggle_pause(self):
        if self.is_paused:
            pause_event.set()
            self.is_paused = False
            self.pause_btn.config(text="一時停止", bg="#FFA500")
            self.status_label.config(text="処理中...", fg="green")
            log("一時停止解除")
        else:
            pause_event.clear()
            self.is_paused = True
            self.pause_btn.config(text="再開", bg="#0000FF")
            self.status_label.config(text="一時停止中", fg="orange")
            log("一時停止実行")
    
    def force_stop(self):
        result = messagebox.askyesno(
            "確認", 
            "本当に処理を強制終了しますか？\n\n"
            "全てのLDPlayerプロセスが終了し、\n"
            "現在の進捗は保存されますが、\n"
            "未完了の処理は中断されます。"
        )
        if result:
            log("強制終了が要求されました")
            stop_event.set()
            self.status_label.config(text="停止中...", fg="red")
            self.pause_btn.config(state="disabled")
            self.stop_btn.config(state="disabled")
            
            threading.Thread(target=kill_all_ldplayers, daemon=True).start()
            
            def delayed_exit():
                time.sleep(2)
                log("プログラムを終了します")
                os._exit(0)
            
            threading.Thread(target=delayed_exit, daemon=True).start()
    
    def on_close(self):
        result = messagebox.askyesno(
            "確認",
            "制御パネルを閉じますか？\n\n"
            "処理は継続されます。"
        )
        if result:
            self.window.destroy()
    
    def show(self):
        self.window.deiconify()

def main_gui():
    root = Tk()
    root.title("アカウント作成ツール")
    root.geometry("500x400")
    
    Label(root, text="アカウント自動作成ツール", font=("Arial", 16, "bold")).pack(pady=20)
    
    frame = Frame(root)
    frame.pack(pady=20)
    
    default_count = "10"
    default_password = "qwer1234"
    default_csv = "level5.csv"
    default_output = "hisaacc.csv"
    
    Label(frame, text="作成件数:", font=("Arial", 10)).grid(row=0, column=0, sticky="e", padx=10, pady=10)
    count_entry = Entry(frame, width=20, font=("Arial", 10))
    count_entry.insert(0, default_count)
    count_entry.grid(row=0, column=1, padx=10, pady=10)
    
    Label(frame, text="パスワード:", font=("Arial", 10)).grid(row=1, column=0, sticky="e", padx=10, pady=10)
    password_entry = Entry(frame, width=20, font=("Arial", 10))
    password_entry.insert(0, default_password)
    password_entry.grid(row=1, column=1, padx=10, pady=10)
    
    Label(frame, text="メールCSV:", font=("Arial", 10)).grid(row=2, column=0, sticky="e", padx=10, pady=10)
    csv_entry = Entry(frame, width=20, font=("Arial", 10))
    csv_entry.insert(0, default_csv)
    csv_entry.grid(row=2, column=1, padx=10, pady=10)
    
    def browse_csv():
        path = filedialog.askopenfilename(
            title="メールCSVを選択",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        if path:
            csv_entry.delete(0, END)
            csv_entry.insert(0, path)
    
    Button(frame, text="参照", command=browse_csv).grid(row=2, column=2, padx=5)
    
    Label(frame, text="出力ファイル:", font=("Arial", 10)).grid(row=3, column=0, sticky="e", padx=10, pady=10)
    output_entry = Entry(frame, width=20, font=("Arial", 10))
    output_entry.insert(0, default_output)
    output_entry.grid(row=3, column=1, padx=10, pady=10)
    
    def browse_output():
        path = filedialog.asksaveasfilename(
            title="出力ファイルを選択",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        if path:
            output_entry.delete(0, END)
            output_entry.insert(0, path)

    Button(frame, text="参照", command=browse_output).grid(row=3, column=2, padx=5)
    
    result_label = Label(root, text="", font=("Arial", 10), fg="blue")
    result_label.pack(pady=10)
    
    def start_process():
        try:
            count = int(count_entry.get().strip())
        except ValueError:
            messagebox.showerror("入力エラー", "作成件数は数字で入力してください")
            return
        
        password = password_entry.get().strip()
        csv_path = csv_entry.get().strip()
        output_path = output_entry.get().strip()
        
        if not password:
            messagebox.showerror("入力エラー", "パスワードを入力してください")
            return
        
        if not os.path.exists(csv_path):
            messagebox.showerror("ファイルエラー", f"メールCSVが見つかりません:\n{csv_path}")
            return
        
        confirm_msg = (
            f"以下の設定で処理を開始します:\n\n"
            f"作成件数: {count}\n"
            f"パスワード: {password}\n"
            f"メールCSV: {csv_path}\n"
            f"出力ファイル: {output_path}\n\n"
            f"よろしいですか？"
        )
        
        if not messagebox.askyesno("確認", confirm_msg):
            return
        
        root.withdraw()
        
        try:
            # 修正: グローバルイベントを完全リセット
            global group_events
            pause_event.set()
            stop_event.clear()
            group_events = [threading.Event() for _ in range(4)]
            group_events[0].set()  # グループ1のみ最初から実行可能

            adb_path, device_mapping = get_device_ldplayer_mapping()

            if not adb_path or not device_mapping:
                messagebox.showerror("エラー", "デバイスマッピングに失敗しました")
                root.deiconify()
                return

            email_manager = EmailManager(csv_path)
            remaining_emails = email_manager.get_remaining_count()
            total_required = len(device_mapping) * count

            if remaining_emails < total_required:
                messagebox.showerror(
                    "メール不足",
                    f"メールが不足しています\n\n"
                    f"必要: {total_required}件\n"
                    f"利用可能: {remaining_emails}件"
                )
                root.deiconify()
                return

            start_msg = (
                f"処理を開始します\n\n"
                f"検出端末: {len(device_mapping)}台\n"
                f"各端末で{count}件作成\n"
                f"合計: {total_required}件\n\n"
                f"制御パネルが表示されます"
            )
            messagebox.showinfo("処理開始", start_msg)

            control_panel = ControlPanel(count, len(device_mapping))
            control_panel.show()

            def background_process():
                devices = list(device_mapping.items())
                total_instances = len(devices)

                group_count = 4
                with ThreadPoolExecutor(max_workers=total_instances) as executor:
                    futures = []

                    for idx, (device_id, ld_index) in enumerate(devices):
                        group = (idx % group_count) + 1 
                        future = executor.submit(
                            device_worker,
                            adb_path, device_id, ld_index, email_manager,
                            count, output_path, password,
                            idx, total_instances, group
                        )
                        futures.append((device_id, future))

                total_success = 0
                for device_id, future in futures:
                    try:
                        success_count = future.result()
                        total_success += success_count
                    except Exception as e:
                        log(f"端末 {device_id} でエラー: {e}", device_id)

                email_manager.clean_csv_file()
                remaining_after = email_manager.get_remaining_count()

                if stop_event.is_set():
                    result_msg = (
                        f"処理が中断されました\n\n"
                        f"成功件数: {total_success}/{total_required}\n"
                        f"残りメール: {remaining_after}件\n\n"
                        f"結果は {output_path} に保存されました"
                    )
                else:
                    result_msg = (
                        f"処理が完了しました！\n\n"
                        f"総成功件数: {total_success}/{total_required}\n"
                        f"残りメール: {remaining_after}件\n\n"
                        f"結果は {output_path} に保存されました"
                    )

                messagebox.showinfo("完了", result_msg)
                root.deiconify()
                result_label.config(text="処理完了しました", fg="green")
            
            threading.Thread(target=background_process, daemon=True).start()

        except Exception as e:
            messagebox.showerror("エラー", f"処理中にエラーが発生しました:\n{str(e)}")
            root.deiconify()

    Button(root, text="処理開始", command=start_process, 
           font=("Arial", 12, "bold"), bg="#4CAF50", fg="white",
           width=20, height=2).pack(pady=20)
    
    Button(root, text="終了", command=root.destroy, 
           font=("Arial", 10), width=10).pack(pady=5)
    
    root.mainloop()

if __name__ == "__main__":
    try:
        main_gui()
    except Exception as e:
        root = Tk()
        root.withdraw()
        messagebox.showerror("致命的エラー", f"エラーが発生しました:\n{str(e)}")
        root.destroy()
        input("処理終了しました。Enterキーを押して閉じてください...")