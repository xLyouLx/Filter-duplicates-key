import re
import os
import time
import base64
import json
import sys
from collections import defaultdict
from urllib.parse import parse_qs, unquote
import math

# Unified colored print with reset and flush for stability
def colored_print(text, color='White'):
    colors = {
        'Green': '\033[92m',
        'Red': '\033[91m',
        'Yellow': '\033[93m',
        'Cyan': '\033[96m',
        'Blue': '\033[94m',
        'Magenta': '\033[95m',
        'Gray': '\033[90m',
        'White': '\033[97m',
    }
    reset = '\033[0m'
    code = colors.get(color, '')
    print(f"{code}{text}{reset}")
    sys.stdout.flush()

def normalize_uuid(uuid):
    if not uuid:
        return ""
    uuid = uuid.strip().lower()
    uuid = uuid.replace('{', '').replace('}', '')
    return uuid

def normalize_server(server):
    if not server:
        return ""
    server = server.strip()
    if server.startswith('[') and server.endswith(']'):
        server = server[1:-1]
    return server

def normalize_port(port):
    if not port:
        return "443"
    return str(port).strip()

def normalize_param(value):
    if not value:
        return ""
    return value.strip().lower()

def parse_vless(link):
    if not link.startswith('vless://'):
        return None
    
    try:
        link = link[8:]
        
        if '#' in link:
            main_part, name_part = link.split('#', 1)
            name = unquote(name_part)
        else:
            main_part = link
            name = ""
        
        if '?' in main_part:
            addr_part, param_part = main_part.split('?', 1)
        else:
            addr_part = main_part
            param_part = ""
        
        if '@' in addr_part:
            uuid, server_part = addr_part.split('@', 1)
            uuid = normalize_uuid(uuid)
        else:
            uuid = ""
            server_part = addr_part
        
        server = ""
        port = "443"
        
        if ':' in server_part:
            if server_part.startswith('['):
                ipv6_end = server_part.index(']')
                server = server_part[1:ipv6_end]
                port_part = server_part[ipv6_end + 1:]
                if port_part.startswith(':'):
                    port = port_part[1:]
            else:
                parts = server_part.split(':')
                server = parts[0]
                port = parts[1] if len(parts) > 1 else "443"
        else:
            server = server_part
        
        server = normalize_server(server)
        port = normalize_port(port)
        
        params = parse_qs(param_part)
        
        security   = normalize_param(params.get('security',   [''])[0])
        type_param = normalize_param(params.get('type',       [''])[0])
        host       = normalize_param(params.get('host',       [''])[0])
        path       = normalize_param(params.get('path',       [''])[0])
        sni        = normalize_param(params.get('sni',        [''])[0])
        flow       = normalize_param(params.get('flow',       [''])[0])
        encryption = normalize_param(params.get('encryption', [''])[0])
        pbk        = normalize_param(params.get('pbk',        [''])[0])
        sid        = normalize_param(params.get('sid',        [''])[0])
        fp         = normalize_param(params.get('fp',         [''])[0])
        
        # Ключ без UUID — для reality используем pbk + sid + sni как основной идентификатор
        key_parts = [server, port, security, flow]
        
        if security == 'reality':
            reality_parts = []
            if pbk:
                reality_parts.append(pbk)
            if sid:
                reality_parts.append(sid)
            if sni:
                reality_parts.append(sni)
            
            if reality_parts:
                key_parts.append('|'.join(reality_parts))
        
        key = ':'.join(key_parts)
        
        return {
            'type': 'vless',
            'protocol': 'vless',
            'server': server,
            'port': port,
            'uuid': uuid,
            'security': security,
            'type_param': type_param,
            'host': host,
            'path': path,
            'sni': sni,
            'flow': flow,
            'encryption': encryption,
            'pbk': pbk,
            'sid': sid,
            'fp': fp,
            'name': name,
            'key': key,
            'original': link
        }
    except Exception:
        return None

def parse_vmess(link):
    if not link.startswith('vmess://'):
        return None
    
    try:
        encoded = link[8:]
        padding = 4 - len(encoded) % 4
        if padding != 4:
            encoded += '=' * padding
        
        json_str = base64.b64decode(encoded).decode('utf-8')
        config = json.loads(json_str)
        
        server = normalize_server(config.get('add', ''))
        port = normalize_port(config.get('port', '443'))
        uuid = normalize_uuid(config.get('id', ''))
        security = normalize_param(config.get('security', ''))
        type_param = normalize_param(config.get('type', ''))
        host = normalize_param(config.get('host', ''))
        path = normalize_param(config.get('path', ''))
        sni = normalize_param(config.get('sni', ''))
        net = normalize_param(config.get('net', ''))
        
        key_parts = [server, port, uuid, security, net, type_param]
        if host:
            key_parts.append(host)
        if path:
            key_parts.append(path)
        
        key = ':'.join(key_parts)
        
        return {
            'type': 'vmess',
            'protocol': 'vmess',
            'server': server,
            'port': port,
            'uuid': uuid,
            'security': security,
            'type_param': type_param,
            'host': host,
            'path': path,
            'sni': sni,
            'net': net,
            'ps': config.get('ps', ''),
            'key': key,
            'original': link
        }
    except Exception:
        return None

def parse_trojan(link):
    if not link.startswith('trojan://'):
        return None
    
    try:
        link = link[9:]
        
        if '#' in link:
            main_part, name_part = link.split('#', 1)
            name = unquote(name_part)
        else:
            main_part = link
            name = ""
        
        if '?' in main_part:
            addr_part, param_part = main_part.split('?', 1)
        else:
            addr_part = main_part
            param_part = ""
        
        if '@' in addr_part:
            password, server_part = addr_part.split('@', 1)
            password = password.strip()
        else:
            password = ""
            server_part = addr_part
        
        server = ""
        port = "443"
        
        if ':' in server_part:
            if server_part.startswith('['):
                ipv6_end = server_part.index(']')
                server = server_part[1:ipv6_end]
                port_part = server_part[ipv6_end + 1:]
                if port_part.startswith(':'):
                    port = port_part[1:]
            else:
                parts = server_part.split(':')
                server = parts[0]
                port = parts[1] if len(parts) > 1 else "443"
        else:
            server = server_part
        
        server = normalize_server(server)
        port = normalize_port(port)
        
        params = parse_qs(param_part)
        
        security = normalize_param(params.get('security', [''])[0])
        type_param = normalize_param(params.get('type', [''])[0])
        host = normalize_param(params.get('host', [''])[0])
        path = normalize_param(params.get('path', [''])[0])
        sni = normalize_param(params.get('sni', [''])[0])
        
        key_parts = [server, port, password, security, type_param]
        if host:
            key_parts.append(host)
        if path:
            key_parts.append(path)
        if sni:
            key_parts.append(sni)
        
        key = ':'.join(key_parts)
        
        return {
            'type': 'trojan',
            'protocol': 'trojan',
            'server': server,
            'port': port,
            'password': password,
            'security': security,
            'type_param': type_param,
            'host': host,
            'path': path,
            'sni': sni,
            'name': name,
            'key': key,
            'original': link
        }
    except Exception:
        return None

def parse_shadowsocks(link):
    if not link.startswith('ss://'):
        return None
    
    try:
        link = link[5:]
        
        if '#' in link:
            encoded_part, name = link.split('#', 1)
            name = unquote(name)
        else:
            encoded_part = link
            name = ""
        
        method = ""
        password = ""
        server = ""
        port = "8388"
        
        if '@' in encoded_part:
            method_pass, server_port = encoded_part.split('@', 1)
            padding = 4 - len(method_pass) % 4
            if padding != 4:
                method_pass += '=' * padding
            
            method_password = base64.b64decode(method_pass).decode('utf-8', errors='ignore')
            if ':' in method_password:
                method, password = method_password.split(':', 1)
        else:
            padding = 4 - len(encoded_part) % 4
            if padding != 4:
                encoded_part += '=' * padding
            
            decoded = base64.b64decode(encoded_part).decode('utf-8', errors='ignore')
            server_port = decoded
        
        if ':' in server_port:
            server, port = server_port.split(':', 1)
        
        server = normalize_server(server)
        port = normalize_port(port)
        method = method.strip()
        password = password.strip()
        
        key = f"{server}:{port}:{method}:{password}"
        
        return {
            'type': 'ss',
            'protocol': 'ss',
            'server': server,
            'port': port,
            'method': method,
            'password': password,
            'name': name,
            'key': key,
            'original': f"ss://{encoded_part}#{name}" if name else f"ss://{encoded_part}"
        }
    except Exception:
        return None

def parse_hy(link):
    if not link.startswith('hy://'):
        return None
    
    try:
        link = link[5:]
        
        if '#' in link:
            main_part, name_part = link.split('#', 1)
            name = unquote(name_part)
        else:
            main_part = link
            name = ""
        
        if '?' in main_part:
            addr_part, param_part = main_part.split('?', 1)
        else:
            addr_part = main_part
            param_part = ""
        
        if '@' in addr_part:
            auth, server_part = addr_part.split('@', 1)
            auth = auth.strip()
        else:
            auth = ""
            server_part = addr_part
        
        if ':' in server_part:
            server, port = server_part.split(':', 1)
        else:
            server = server_part
            port = "443"
        
        server = normalize_server(server)
        port = normalize_port(port)
        
        key = f"{server}:{port}:{auth}"
        
        return {
            'type': 'hy',
            'protocol': 'hy',
            'server': server,
            'port': port,
            'auth': auth,
            'name': name,
            'key': key,
            'original': link
        }
    except Exception:
        return None

def parse_link(link):
    link = link.strip()
    if link.startswith('vless://'):
        return parse_vless(link)
    elif link.startswith('vmess://'):
        return parse_vmess(link)
    elif link.startswith('trojan://'):
        return parse_trojan(link)
    elif link.startswith('ss://'):
        return parse_shadowsocks(link)
    elif link.startswith('hy://'):
        return parse_hy(link)
    else:
        if '://' in link:
            protocol = link.split('://')[0]
            return {
                'type': protocol,
                'protocol': protocol,
                'server': '',
                'port': '',
                'key': link,
                'original': link,
                'parsed': False
            }
        return None

def show_processing_log(log_entries):
    os.system('cls' if os.name == 'nt' else 'clear')
    colored_print("Лог обработки...\n", 'Cyan')
    
    for text, color in log_entries:
        colored_print(text, color)

def show_statistics(processing_time, unique_count, total_links, 
                    duplicates_found, protocols_count, key_stats):
    os.system('cls' if os.name == 'nt' else 'clear')
    
    colored_print(f"Готово за {processing_time} сек\n", 'Cyan')
    
    colored_print(f"Уникальных: {unique_count}", 'Green')
    colored_print(f"Дубликатов: {duplicates_found}", 'Red')
    colored_print(f"Всего ссылок: {total_links}", 'White')
    
    percentage = round((unique_count / total_links) * 100, 2) if total_links > 0 else 0
    colored_print(f"Процент уникальных: {percentage}%\n", 'White')
    
    if protocols_count:
        colored_print("По протоколам:", 'Cyan')
        for protocol, count in sorted(protocols_count.items()):
            color = 'Green'
            if protocol == "unknown":
                color = 'Gray'
            elif protocol == "vless":
                color = 'Blue'
            elif protocol == "vmess":
                color = 'Magenta'
            elif protocol == "trojan":
                color = 'Yellow'
            colored_print(f"  {protocol.ljust(10)}: {count}", color)
        print()
    
    if key_stats:
        colored_print("Топ повторяющихся ключей:", 'Cyan')
        for key, count in sorted(key_stats.items(), key=lambda x: x[1], reverse=True)[:10]:
            if count > 1:
                colored_print(f"  {key[:60]}...: {count} раз", 'Gray')
        print()
    
    colored_print(f"subYes.txt  > {unique_count} уникальных ссылок", 'Green')
    colored_print(f"subNo.txt   > {duplicates_found} дубликатов\n", 'Red')
    
    colored_print("Фильтр дубликатов подписок", 'Cyan')
    colored_print("github.com/xLyouLx", 'Gray')
    colored_print("<3", 'Red')

def get_short_uuid(uuid):
    if not uuid:
        return "нет"
    return uuid[:8] + "..." if len(uuid) > 8 else uuid

def get_short_password(password):
    if not password:
        return "нет"
    return password[:8] + "..." if len(password) > 8 else password

def estimate_processing_time(total_links):
    base_time = 0.1
    per_link_time = 0.005
    estimated = base_time + (per_link_time * total_links)
    estimated = max(estimated, 0.2)
    estimated = round(estimated, 1)
    
    if estimated < 60:
        return f"~{estimated} сек"
    else:
        minutes = math.floor(estimated / 60)
        seconds = round(estimated % 60)
        return f"~{minutes} мин {seconds} сек"

def start_duplicate_filter():
    script_path = os.path.dirname(os.path.abspath(__file__))
    sub_folder = os.path.join(script_path, "sub")
    
    if not os.path.exists(sub_folder):
        os.makedirs(sub_folder)
        colored_print(f"Создана папка: {sub_folder}", 'Green')
    
    txt_files = [f for f in os.listdir(sub_folder) if f.endswith('.txt')]
    
    if not txt_files:
        colored_print("В папке 'sub' не найдено txt файлов", 'Red')
        colored_print(f"Положите txt файлы с подписками в папку: {sub_folder}", 'Gray')
        if os.name == 'nt':
            input()
        return
    
    colored_print(f"Найдено файлов в папке 'sub': {len(txt_files)}", 'Cyan')
    for i, file_name in enumerate(txt_files, 1):
        file_path = os.path.join(sub_folder, file_name)
        file_size = os.path.getsize(file_path)
        print(f"  {i}. {file_name} ({file_size} байт)")
    print()
    
    all_links = []
    for file_name in txt_files:
        file_path = os.path.join(sub_folder, file_name)
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                links = [line.strip() for line in f if line.strip()]
            all_links.extend(links)
            colored_print(f"Загружено из {file_name}: {len(links)} ссылок", 'Green')
        except Exception as e:
            colored_print(f"Ошибка чтения {file_name}: {str(e)}", 'Red')
    
    if not all_links:
        colored_print("Все файлы пустые или ошибка чтения", 'Red')
        if os.name == 'nt':
            input()
        return
    
    estimated_time = estimate_processing_time(len(all_links))
    
    os.system('cls' if os.name == 'nt' else 'clear')
    colored_print("Улучшенный Duplicate Filter 2025", 'Cyan')
    colored_print(f"Папка: {sub_folder}", 'Gray')
    colored_print("Обрабатываются все .txt файлы из папки sub", 'Gray')
    colored_print(f"Общее количество ссылок: {len(all_links)}", 'Gray')
    colored_print(f"Примерное время обработки: {estimated_time}", 'Yellow')
    print()
    colored_print("Идентификация по: server:port:security:flow + (pbk|sid|sni для reality)", 'Gray')
    colored_print("UUID больше НЕ учитывается при поиске дубликатов\n", 'Gray')
    
    start_time = time.time()
    unique_links = []
    duplicate_links = []
    seen_keys = set()
    log_entries = []
    protocols_count = defaultdict(int)
    duplicates_found = 0
    key_stats = defaultdict(int)
    
    colored_print("Обработка ссылок...\n", 'White')
    
    for link in all_links:
        parsed = parse_link(link)
        
        if parsed and 'key' in parsed:
            protocol_type = parsed.get('protocol', parsed.get('type', 'unknown'))
            protocols_count[protocol_type] += 1
            
            key = parsed['key']
            key_stats[key] += 1
            
            if key in seen_keys:
                duplicate_links.append(link)
                duplicates_found += 1
                
                server_info = f"{parsed.get('server', 'N/A')}:{parsed.get('port', 'N/A')}"
                if parsed.get('uuid'):
                    id_info = f"UUID: {get_short_uuid(parsed['uuid'])}"
                elif parsed.get('password'):
                    id_info = f"Pass: {get_short_password(parsed['password'])}"
                else:
                    id_info = "нет идентификатора"
                
                text = f"  - [{protocol_type}] Дубликат {server_info} ({id_info})"
                log_entries.append((text, 'Red'))
                colored_print(text, 'Red')
            else:
                seen_keys.add(key)
                unique_links.append(link)
                
                server_info = f"{parsed.get('server', 'N/A')}:{parsed.get('port', 'N/A')}"
                protocol_info = protocol_type
                
                if protocol_type == 'vless':
                    info = f"UUID: {get_short_uuid(parsed.get('uuid', ''))}"
                    extra = []
                    if parsed.get('security'):
                        extra.append(f"sec:{parsed['security']}")
                    if parsed.get('flow'):
                        extra.append(f"flow:{parsed['flow']}")
                    if parsed.get('pbk'):
                        extra.append(f"pbk:{parsed['pbk'][:6]}...")
                    if parsed.get('sid'):
                        extra.append(f"sid:{parsed['sid']}")
                    if parsed.get('sni'):
                        extra.append(f"sni:{parsed['sni'][:10]}...")
                    if extra:
                        info += f" ({', '.join(extra)})"
                elif protocol_type == 'vmess':
                    info = f"UUID: {get_short_uuid(parsed.get('uuid', ''))}"
                    extra = []
                    if parsed.get('net'):
                        extra.append(f"net:{parsed['net']}")
                    if parsed.get('type_param'):
                        extra.append(f"type:{parsed['type_param']}")
                    if extra:
                        info += f" ({', '.join(extra)})"
                elif protocol_type == 'trojan':
                    info = f"Pass: {get_short_password(parsed.get('password', ''))}"
                elif protocol_type == 'ss':
                    info = f"Method: {parsed.get('method', 'неизвестно')}"
                else:
                    info = protocol_type
                
                text = f"  + [{protocol_info}] Уникально {server_info} ({info})"
                log_entries.append((text, 'Green'))
                colored_print(text, 'Green')
        else:
            protocols_count['unknown'] += 1
            
            if link in seen_keys:
                duplicate_links.append(link)
                duplicates_found += 1
                text = f"  - [unknown] Дубликат неизвестного формата"
                log_entries.append((text, 'Red'))
                colored_print(text, 'Red')
            else:
                seen_keys.add(link)
                unique_links.append(link)
                text = f"  ? [unknown] Неизвестный формат (уникально)"
                log_entries.append((text, 'Yellow'))
                colored_print(text, 'Yellow')
    
    output_yes = os.path.join(script_path, "subYes.txt")
    output_no  = os.path.join(script_path, "subNo.txt")
    
    try:
        with open(output_yes, 'w', encoding='utf-8') as f:
            f.write('\n'.join(unique_links))
        with open(output_no, 'w', encoding='utf-8') as f:
            f.write('\n'.join(duplicate_links))
        
        colored_print(f"\nСохранено в {output_yes}: {len(unique_links)} уникальных", 'Green')
        colored_print(f"Сохранено в {output_no}: {len(duplicate_links)} дубликатов", 'Red')
    except Exception as e:
        colored_print(f"Ошибка сохранения: {str(e)}", 'Red')
    
    processing_time = round(time.time() - start_time, 1)
    duplicate_key_stats = {k: v for k, v in key_stats.items() if v > 1}
    
    show_statistics(processing_time, len(unique_links), len(all_links), 
                    duplicates_found, dict(protocols_count), duplicate_key_stats)
    
    show_stats = True
    while True:
        if show_stats:
            prompt = "\nEnter — выход, Y — показать лог обработки"
        else:
            prompt = "\nEnter — выход, Y — вернуться к статистике"
        
        try:
            user_input = input(prompt).strip().lower()
        except KeyboardInterrupt:
            break
        
        if user_input == '':
            break
        if user_input == 'y':
            if show_stats:
                show_processing_log(log_entries)
                show_stats = False
            else:
                show_statistics(processing_time, len(unique_links), len(all_links), 
                                duplicates_found, dict(protocols_count), duplicate_key_stats)
                show_stats = True

if __name__ == "__main__":
    try:
        start_duplicate_filter()
    except Exception as e:
        colored_print(f"\nКритическая ошибка: {str(e)}", 'Red')
        import traceback
        traceback.print_exc()
        if os.name == 'nt':
            input()