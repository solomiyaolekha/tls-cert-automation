import heapq
import sys
import os
import argparse
from scanners.ssl_scanner import HttpsCertificateScanner
from crypto.crypto import CsrGenerator, CertificateSigner
from utils.reporter import ReportManager
from utils.logger import setup_logger

# Додаємо шлях для коректних імпортів модулів
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def main():
    # --- 1. НАЛАШТУВАННЯ ARGPARSE 
    parser = argparse.ArgumentParser(description="TLS Certificate Automation Tool")
    
    # Використовуємо твої назви параметрів
    parser.add_argument('--domain', nargs='+', help="Список доменів для перевірки")
    parser.add_argument('--expirationdays', type=int, help="Поріг днів до закінчення")
    parser.add_argument('--yes', '-y', action='store_true', help="Автоматично погоджуватися на перевипуск сертифікатів")
    
    args = parser.parse_args()

    # --- 2. ІНТЕРАКТИВНЕ ВВЕДЕННЯ З ДЕФОЛТНИМИ ЗНАЧЕННЯМИ ---
    
    # Обробка доменів
    if not args.domain:
        print("\n🌐 Введіть домени через пробіл (або просто Enter для дефолтних сайтів):")
        user_input = input("> ").strip()
        # Дефолтні домени, якщо нічого не введено
        endpoints = user_input.split() if user_input else ["google.com", "example.com", "expired.badssl.com"]
    else:
        endpoints = args.domain

    # Обробка порогу днів
    if args.expirationdays is None:
        print(f"⏳ Введіть поріг днів (або Enter для дефолтних 30 днів):")
        days_input = input("> ").strip()
        # Дефолтні 30 днів, якщо не число або порожньо
        threshold = int(days_input) if days_input.isdigit() else 30
    else:
        threshold = args.expirationdays

    # --- 3. ІНІЦІАЛІЗАЦІЯ ТА СКАНУВАННЯ ---
    logger = setup_logger()
    logger.info(f"Запуск: домени={endpoints}, поріг={threshold}")
    
    scanner = HttpsCertificateScanner(threshold=threshold)
    reporter = ReportManager()
    
    priority_queue = []
    all_results = []

    print(f"\n📡 Крок 1: Опитування сайтів: {endpoints}...")
    for host in endpoints:
        try:
            info = scanner.get_info(host)
            if info:
                # Пріоритетна черга (Advanced Data Structure)
                heapq.heappush(priority_queue, info)
                all_results.append(info)
        except Exception as e:
            logger.error(f"Помилка при перевірці {host}: {e}")
            print(f"❌ Не вдалося отримати дані для {host}")

    print("\n--- Результати моніторингу (відсортовані за критичністю) ---")
    
    certs_to_process = []
    while len(priority_queue) > 0:
        certs_to_process.append(heapq.heappop(priority_queue))

    # --- 4. СУВОРА ОБРОБКА ТА ПЕРЕВИПУСК ---
    for cert in certs_to_process:
        print(f"\n[{cert.status.upper()}] {cert.domain} - Залишилось: {cert.days_left} днів")

        if cert.status == "expiring_soon" or cert.status == "expired":
            while True:
                if args.yes:
                    ans = 'y'
                else:
                    ans = input(f"⚠️ Бажаєте перевипустити сертифікат для {cert.domain}? (y/n): ").strip().lower()
                
                if ans == 'y':
                    csr_gen = CsrGenerator(key_path="private.key")
                    csr_path = csr_gen.generate_csr(cert.domain)
                    logger.info(f"Згенеровано CSR для {cert.domain}")

                    print("Оберіть дію: 1 - Самопідписати, 2 - Тільки CSR:")
                    choice = input("> ").strip()
                    
                    if choice == "1":
                        signer = CertificateSigner()
                        signer.self_sign_csr(csr_path, "private.key", f"{cert.domain}.crt")
                        print(f"✅ Сертифікат {cert.domain}.crt успішно створено!")
                    break 
                
                elif ans == 'n':
                    print(f"⏩ Дія для {cert.domain} скасована.")
                    break 
                
                else:
                    print("❌ Помилка: введіть лише 'y' або 'n'.")

    # --- 5. ФІНАЛІЗАЦІЯ ---
    reporter.save_json_report(all_results)
    print("\n✅ Роботу завершено. Звіт збережено у cert_report.json")

if __name__ == "__main__":
    main()