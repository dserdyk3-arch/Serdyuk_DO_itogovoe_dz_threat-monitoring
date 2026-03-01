"""
Автоматизированный мониторинг и реагирование на угрозы
Скрипт для анализа логов веб-сервера и проверки IP через VirusTotal
"""

import re
import json
import csv
from collections import Counter
import os
import requests
import matplotlib.pyplot as plt
import pandas as pd

# ------------------- ЧАСТЬ 1: ЗАГРУЗКА ДАННЫХ -------------------

def load_logs(file_path):
    """
    Загружает логи из файла
    """
    print("[1] Загружаем логи из файла...")
    logs = []
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            for line in file:
                logs.append(line.strip())
        print(f"    Загружено {len(logs)} строк лога")
        return logs
    except FileNotFoundError:
        print(f"    ОШИБКА: Файл {file_path} не найден!")
        return []

def extract_ips_from_logs(logs):
    """
    Достает IP-адреса из строк лога
    """
    print("[2] Извлекаем IP-адреса...")
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    ips = []
    
    for line in logs:
        match = re.search(ip_pattern, line)
        if match:
            ips.append(match.group())
    
    print(f"    Найдено {len(ips)} IP-адресов")
    return ips

# ------------------- ЧАСТЬ 2: РАБОТА С API (С ИМИТАЦИЕЙ) -------------------

def check_ip_virustotal(ip, use_cache=True):
    """
    Проверяет IP через VirusTotal (с имитацией для надежности)
    """
    print(f"    Проверяем IP {ip} через VirusTotal...")
    
    cache_file = "vt_cache.json"
    cache = {}
    
    # Загружаем кэш если есть
    if use_cache and os.path.exists(cache_file):
        with open(cache_file, 'r') as f:
            cache = json.load(f)
        
        if ip in cache:
            print(f"        Данные из кэша")
            return cache[ip]
    
    # Имитация запроса к API
    # Список "плохих" IP для демонстрации
    bad_ips = ['192.168.1.105', '10.0.0.55', '172.16.1.200', '203.0.113.45']
    suspicious_ips = ['192.168.1.100', '192.168.1.101']  # Эти будем считать подозрительными
    
    result = {
        'ip': ip,
        'malicious': ip in bad_ips,
        'suspicious': ip in suspicious_ips,
        'source': 'simulated'
    }
    
    # Сохраняем в кэш
    cache[ip] = result
    with open(cache_file, 'w') as f:
        json.dump(cache, f, indent=2)
    
    if result['malicious']:
        print(f"        РЕЗУЛЬТАТ: ВРЕДОНОСНЫЙ IP!")
    elif result['suspicious']:
        print(f"        РЕЗУЛЬТАТ: подозрительный IP")
    else:
        print(f"        РЕЗУЛЬТАТ: чистый IP")
    
    return result

# ------------------- ЧАСТЬ 3: АНАЛИЗ -------------------

def analyze_traffic(ips):
    """
    Анализирует трафик: ищет частые запросы и проверяет IP
    """
    print("[3] Анализируем трафик...")
    
    # Считаем частоту запросов с каждого IP
    ip_counts = Counter(ips)
    total_requests = len(ips)
    
    print(f"    Уникальных IP: {len(ip_counts)}")
    print(f"    Всего запросов: {total_requests}")
    
    threats = []
    analyzed_ips = []
    
    # Анализируем ВСЕ уникальные IP (убрал ограничение по count > 5)
    for ip, count in ip_counts.most_common():
        vt_result = check_ip_virustotal(ip)
        
        ip_data = {
            'ip': ip,
            'requests': count,
            'percent': round(count / total_requests * 100, 2),
            'malicious': vt_result['malicious'],
            'suspicious': vt_result['suspicious']
        }
        analyzed_ips.append(ip_data)
        
        if vt_result['malicious'] or vt_result['suspicious']:
            threats.append(ip_data)
    
    return analyzed_ips, threats

# ------------------- ЧАСТЬ 4: РЕАГИРОВАНИЕ -------------------

def respond_to_threats(threats):
    """
    Реагирует на найденные угрозы
    """
    print("\n[4] РЕАГИРОВАНИЕ НА УГРОЗЫ:")
    if not threats:
        print("    Угроз не обнаружено")
        return
    
    for threat in threats:
        threat_type = "ВРЕДОНОСНЫЙ" if threat['malicious'] else "ПОДОЗРИТЕЛЬНЫЙ"
        print(f"    [!] {threat_type} IP {threat['ip']}")
        print(f"        Запросов: {threat['requests']} ({threat['percent']}% от всего трафика)")
        print(f"        Имитация блокировки IP {threat['ip']} в файерволе")
        print(f"        Отправка уведомления администратору\n")

# ------------------- ЧАСТЬ 5: СОХРАНЕНИЕ ОТЧЕТА -------------------

def save_report(data, filename="threat_report.csv"):
    """
    Сохраняет результаты в CSV
    """
    print(f"[5] Сохраняем отчет в {filename}")
    
    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['ip', 'requests', 'percent', 'malicious', 'suspicious']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for row in data:
            writer.writerow(row)
    
    print(f"    Сохранено {len(data)} записей")
    
    # Для наглядности покажем первые строки отчета
    print("\n    Первые строки отчета:")
    for row in data[:5]:
        status = "ВРЕДОНОСНЫЙ" if row['malicious'] else "ПОДОЗРИТЕЛЬНЫЙ" if row['suspicious'] else "чистый"
        print(f"        {row['ip']}: {row['requests']} запросов, {row['percent']}% - {status}")

# ------------------- ЧАСТЬ 6: ПОСТРОЕНИЕ ГРАФИКА -------------------

def plot_top_ips(data, filename="top_ips.png"):
    """
    Строит график топ IP по количеству запросов
    """
    print(f"\n[6] Строим график и сохраняем в {filename}")
    
    # Берем топ-10 IP для графика
    top_10 = data[:10]
    
    ips = [row['ip'] for row in top_10]
    requests_count = [row['requests'] for row in top_10]
    
    # Цвета в зависимости от статуса
    colors = []
    for row in top_10:
        if row['malicious']:
            colors.append('red')
        elif row['suspicious']:
            colors.append('orange')
        else:
            colors.append('blue')
    
    plt.figure(figsize=(12, 6))
    bars = plt.bar(ips, requests_count, color=colors)
    plt.xlabel('IP адрес')
    plt.ylabel('Количество запросов')
    plt.title('Топ-10 IP адресов по количеству запросов')
    plt.xticks(rotation=45, ha='right')
    
    # Добавляем значения на столбцы
    for bar, count in zip(bars, requests_count):
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2., height,
                f'{count}', ha='center', va='bottom')
    
    # Легенда
    from matplotlib.patches import Patch
    legend_elements = [
        Patch(facecolor='red', label='Вредоносный (malicious)'),
        Patch(facecolor='orange', label='Подозрительный (suspicious)'),
        Patch(facecolor='blue', label='Нормальный')
    ]
    plt.legend(handles=legend_elements)
    
    plt.tight_layout()
    plt.savefig(filename, dpi=100)
    print(f"    График сохранен")

# ------------------- ГЛАВНАЯ ФУНКЦИЯ -------------------

def main():
    """
    Основная функция программы
    """
    print("=" * 60)
    print("   МОНИТОРИНГ БЕЗОПАСНОСТИ")
    print("=" * 60)
    
    # Этап 1: Загрузка логов
    logs = load_logs("access.log")
    if not logs:
        print("Нет логов для анализа. Завершение.")
        return
    
    # Этап 1 (продолжение): Извлечение IP
    ips = extract_ips_from_logs(logs)
    
    # Этап 2 и 3: Анализ
    analyzed_ips, threats = analyze_traffic(ips)
    
    # Этап 3: Реагирование
    respond_to_threats(threats)
    
    # Этап 4: Сохранение отчета и графика
    if analyzed_ips:
        save_report(analyzed_ips)
        plot_top_ips(analyzed_ips)
    else:
        print("Нет данных для отчета")
    
    print("\n" + "=" * 60)
    print("   РАБОТА ЗАВЕРШЕНА")
    print("=" * 60)
    print(f"   Всего проанализировано IP: {len(analyzed_ips)}")
    print(f"   Найдено угроз: {len(threats)}")
    print(f"   Отчет сохранен: threat_report.csv")
    print(f"   График сохранен: top_ips.png")
    print("=" * 60)

# Запуск программы
if __name__ == "__main__":
    main()