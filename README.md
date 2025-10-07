import requests
from requests.exceptions import RequestException

# Использование стандартных названий переменных и функций для совместимости

def analyze_headers(target_url: str):
    """
    Выполняет HTTP GET запрос и анализирует заголовки ответа.
    
    Анализируются основные заголовки безопасности, а также заголовок X-Powered-By
    для определения технологического стека.
    
    ПРИМЕЧАНИЕ: В реальных условиях требуется retry-логика и обработка перенаправлений.
    """
    try:
        # Установка таймаута 5 секунд для предотвращения зависания
        response = requests.get(target_url, timeout=5, allow_redirects=False)
        
        # Основные результаты
        results = {
            "status_code": response.status_code,
            "url": target_url,
            "security_headers": {},
            "technology_info": None,
            "error": None
        }
        
        headers = {k.lower(): v for k, v in response.headers.items()}
        
        # 1. Анализ заголовков безопасности (Security Headers)
        security_list = [
            "strict-transport-security", # HSTS
            "content-security-policy",   # CSP
            "x-content-type-options",    # Защита от MIME-sniffing
            "x-frame-options"            # Защита от Clickjacking
        ]
        
        for header in security_list:
            if header in headers:
                results["security_headers"][header.upper()] = "✅ Присутствует"
            else:
                results["security_headers"][header.upper()] = "❌ Отсутствует/Слабый"

        # 2. Определение технологического стека (Technology Detection)
        if 'x-powered-by' in headers:
            results["technology_info"] = f"X-Powered-By: {headers['x-powered-by']}"
        elif 'server' in headers:
             results["technology_info"] = f"Server: {headers['server']}"
        else:
             results["technology_info"] = "Не определен"
        
        return results

    except RequestException as e:
        return {
            "url": target_url,
            "error": f"Ошибка запроса: {type(e).__name__} - {str(e)}",
            "status_code": None
        }
    except Exception as e:
        return {
            "url": target_url,
            "error": f"Непредвиденная ошибка: {str(e)}",
            "status_code": None
        }

if __name__ == "__main__":
    # Для запуска требуется 'pip install requests'
    target = "https://httpbin.org/headers" # Пример тестового ресурса
    print(f"--- Анализ заголовков для: {target} ---")
    
    report = analyze_headers(target)
    
    if report.get('error'):
        print(f"Ошибка: {report['error']}")
    else:
        print(f"Код статуса: {report['status_code']}")
        print("\n[Заголовки безопасности]")
        for k, v in report['security_headers'].items():
            print(f"- {k}: {v}")
        
        print(f"\n[Информация о Технологии]: {report['technology_info']}")
