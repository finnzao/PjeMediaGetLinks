#!/usr/bin/env python3
"""
Automação para captura de links de mídia do sistema PJE
Autor: Sistema Automatizado
Data: 2025
"""

import requests
import re
import json
import logging
import time
import pickle
import os
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urljoin, unquote
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from dotenv import load_dotenv

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('pje_automation.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Configurações
@dataclass
class Config:
    """Configurações da aplicação"""
    base_url: str = "https://midias.pje.jus.br"
    login_endpoint: str = "/midias/web/site/login"
    audiencia_endpoint: str = "/midias/web/audiencia/index"
    max_retries: int = 3
    timeout: int = 30
    delay_between_requests: float = 1.0
    output_dir: str = "downloads"
    session_dir: str = ".sessions"
    session_lifetime_hours: int = 8
    
    # Headers padrão
    headers: Dict[str, str] = field(default_factory=lambda: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'pt-BR,pt;q=0.9,en;q=0.8',
        'Accept-Encoding': 'gzip, deflate, br',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1'
    })

@dataclass
class ProcessoInfo:
    """Informações de um processo"""
    numero: str
    data: Optional[str] = None
    tipo: Optional[str] = None
    juiz: Optional[str] = None
    descricao: Optional[str] = None
    status: Optional[str] = None
    links_midia: List[Dict[str, str]] = field(default_factory=list)

@dataclass
class SessionInfo:
    """Informações da sessão salva"""
    cpf: str
    cookies: Dict
    created_at: datetime
    last_used: datetime

class PJEAutomation:
    """Classe principal para automação do PJE"""
    
    def __init__(self, config: Config = None):
        self.config = config or Config()
        self.session = self._create_session()
        self.processos_info: Dict[str, ProcessoInfo] = {}
        self._cpf_atual: Optional[str] = None
        self._senha_atual: Optional[str] = None
        self._session_info: Optional[SessionInfo] = None
        
        # Criar diretórios necessários
        Path(self.config.output_dir).mkdir(parents=True, exist_ok=True)
        Path(self.config.session_dir).mkdir(parents=True, exist_ok=True)
        
    def _create_session(self) -> requests.Session:
        """Cria sessão com retry automático"""
        session = requests.Session()
        
        # Configurar retry
        retry_strategy = Retry(
            total=self.config.max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "POST", "PUT", "DELETE", "OPTIONS", "TRACE"]
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Configurar headers padrão
        session.headers.update(self.config.headers)
        
        # Configurar para seguir redirecionamentos mas com limite
        session.max_redirects = 10
        
        return session
    
    def _get_session_file_path(self, cpf: str) -> Path:
        """Retorna o caminho do arquivo de sessão para um CPF"""
        cpf_limpo = re.sub(r'[^\d]', '', cpf)
        return Path(self.config.session_dir) / f"session_{cpf_limpo}.pkl"
    
    def _save_session(self, cpf: str):
        """Salva a sessão atual em arquivo"""
        try:
            # Converter cookies para dict simples, evitando duplicatas
            cookies_dict = {}
            for cookie in self.session.cookies:
                # Use o domínio+path+nome como chave para evitar duplicatas
                key = f"{cookie.domain}{cookie.path}{cookie.name}"
                cookies_dict[key] = {
                    'name': cookie.name,
                    'value': cookie.value,
                    'domain': cookie.domain,
                    'path': cookie.path,
                    'secure': cookie.secure,
                    'expires': cookie.expires
                }
            
            session_info = SessionInfo(
                cpf=cpf,
                cookies=cookies_dict,
                created_at=datetime.now(),
                last_used=datetime.now()
            )
            
            session_file = self._get_session_file_path(cpf)
            with open(session_file, 'wb') as f:
                pickle.dump(session_info, f)
            
            self._session_info = session_info
            logger.info(f"Sessão salva para CPF: {cpf[:3]}...{cpf[-3:]}")
            
        except Exception as e:
            logger.error(f"Erro ao salvar sessão: {str(e)}")
    
    def _load_session(self, cpf: str) -> bool:
        """Carrega uma sessão salva"""
        try:
            session_file = self._get_session_file_path(cpf)
            
            if not session_file.exists():
                logger.debug("Arquivo de sessão não encontrado")
                return False
            
            with open(session_file, 'rb') as f:
                session_info: SessionInfo = pickle.load(f)
            
            # Verificar validade da sessão
            idade_sessao = datetime.now() - session_info.created_at
            if idade_sessao > timedelta(hours=self.config.session_lifetime_hours):
                logger.info("Sessão expirada, será necessário novo login")
                session_file.unlink()  # Remove arquivo expirado
                return False
            
            # Limpar cookies existentes
            self.session.cookies.clear()
            
            # Restaurar cookies
            for cookie_data in session_info.cookies.values():
                self.session.cookies.set(
                    cookie_data['name'],
                    cookie_data['value'],
                    domain=cookie_data.get('domain'),
                    path=cookie_data.get('path')
                )
            
            self._session_info = session_info
            
            # Atualizar último uso
            session_info.last_used = datetime.now()
            with open(session_file, 'wb') as f:
                pickle.dump(session_info, f)
            
            logger.info(f"Sessão carregada para CPF: {cpf[:3]}...{cpf[-3:]}")
            return True
            
        except Exception as e:
            logger.error(f"Erro ao carregar sessão: {str(e)}")
            return False
    
    def _verificar_sessao_valida(self) -> bool:
        """Verifica se a sessão atual ainda é válida"""
        try:
            # Tentar acessar uma página protegida
            test_url = urljoin(self.config.base_url, self.config.audiencia_endpoint)
            response = self.session.get(test_url, allow_redirects=True, timeout=10)
            
            # Se não redirecionar para login, a sessão é válida
            if response.status_code == 200 and '/login' not in response.url:
                logger.debug("Sessão ainda válida")
                return True
            else:
                logger.debug("Sessão inválida ou expirada")
                return False
                
        except Exception as e:
            logger.error(f"Erro ao verificar sessão: {str(e)}")
            return False
    
    def _renovar_sessao_se_necessario(self) -> bool:
        """Renova a sessão se necessário"""
        if self._verificar_sessao_valida():
            return True
        
        logger.info("Renovando sessão...")
        
        if self._cpf_atual and self._senha_atual:
            # Limpar cookies antigos
            self.session.cookies.clear()
            
            # Fazer novo login
            if self.login(self._cpf_atual, self._senha_atual):
                logger.info("Sessão renovada com sucesso")
                return True
        
        logger.error("Não foi possível renovar a sessão")
        return False
    
    def validar_processo(self, numero_processo: str) -> bool:
        """Valida formato do número do processo"""
        # Formato: XXXXXXX-XX.XXXX.X.XX.XXXX
        pattern = r'^\d{7}-\d{2}\.\d{4}\.\d\.\d{2}\.\d{4}$'
        return bool(re.match(pattern, numero_processo))
    
    def login(self, cpf: str, senha: str) -> bool:
        """Realiza login no sistema"""
        try:
            # Armazenar credenciais para renovação
            self._cpf_atual = cpf
            self._senha_atual = senha
            
            # Tentar carregar sessão existente
            if self._load_session(cpf):
                if self._verificar_sessao_valida():
                    logger.info("Usando sessão salva válida")
                    return True
                else:
                    logger.info("Sessão salva expirada, fazendo novo login")
            
            # Limpar CPF - remover pontos e hífen
            cpf_limpo = re.sub(r'[^\d]', '', cpf)
            logger.info(f"Iniciando login com CPF: {cpf_limpo[:3]}...{cpf_limpo[-3:]}")
            
            # URL de login
            login_url = urljoin(self.config.base_url, self.config.login_endpoint)
            
            # Desabilitar redirecionamento automático temporariamente
            self.session.max_redirects = 5
            
            # Primeiro, obter a página de login para capturar cookies e CSRF token
            logger.debug("Obtendo página de login...")
            response = self.session.get(login_url, allow_redirects=True)
            response.raise_for_status()
            
            # Verificar se já está logado (redirecionamento direto)
            if '/audiencia/index' in response.url:
                logger.info("Já está logado no sistema")
                self._save_session(cpf)
                return True
            
            # Extrair CSRF token
            soup = BeautifulSoup(response.text, 'html.parser')
            csrf_token = self._extract_csrf_token(soup)
            
            if not csrf_token:
                # Tentar extrair do cookie
                csrf_cookie = self.session.cookies.get('_csrf')
                if csrf_cookie:
                    logger.debug("CSRF token obtido do cookie")
            
            # Preparar dados do formulário
            login_data = {
                'cpf': cpf,  # Enviar CPF com formatação como no exemplo
                'password': senha
            }
            
            # Adicionar CSRF se encontrado
            if csrf_token:
                login_data['_csrf'] = csrf_token
            
            logger.debug(f"Enviando formulário de login para: {login_url}")
            
            # Headers específicos para o POST
            post_headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Referer': login_url,
                'Origin': self.config.base_url
            }
            
            # Realizar login
            response = self.session.post(
                login_url,
                data=login_data,
                headers=post_headers,
                timeout=self.config.timeout,
                allow_redirects=False  # Controlar redirecionamento manualmente
            )
            
            logger.debug(f"Status code do login: {response.status_code}")
            
            # Verificar redirecionamento
            if response.status_code in [302, 303]:
                redirect_url = response.headers.get('Location', '')
                logger.debug(f"Redirecionamento para: {redirect_url}")
                
                # Se redirecionar para audiencia/index, login bem-sucedido
                if '/audiencia/index' in redirect_url:
                    # Seguir o redirecionamento
                    if redirect_url.startswith('http://'):
                        # Converter para HTTPS se necessário
                        redirect_url = redirect_url.replace('http://', 'https://', 1)
                    
                    final_response = self.session.get(redirect_url, allow_redirects=True)
                    
                    if final_response.status_code == 200:
                        logger.info("Login realizado com sucesso")
                        self._save_session(cpf)
                        return True
            
            # Verificar resposta direta
            elif response.status_code == 200:
                # Verificar conteúdo da resposta
                if 'logout' in response.text.lower() or 'sair' in response.text.lower():
                    logger.info("Login realizado com sucesso")
                    self._save_session(cpf)
                    return True
                elif 'senha incorreta' in response.text.lower() or 'cpf inválido' in response.text.lower():
                    logger.error("Credenciais inválidas")
                    return False
                else:
                    # Tentar acessar página de audiências para confirmar
                    test_url = urljoin(self.config.base_url, self.config.audiencia_endpoint)
                    test_response = self.session.get(test_url, allow_redirects=True)
                    
                    if test_response.status_code == 200 and '/login' not in test_response.url:
                        logger.info("Login realizado com sucesso (verificado)")
                        self._save_session(cpf)
                        return True
            
            logger.warning("Login não confirmado, verificando sessão...")
            
            # Última tentativa - verificar se consegue acessar área protegida
            check_url = urljoin(self.config.base_url, self.config.audiencia_endpoint)
            check_response = self.session.get(check_url, allow_redirects=True)
            
            if check_response.status_code == 200 and '/login' not in check_response.url:
                logger.info("Sessão válida confirmada")
                self._save_session(cpf)
                return True
            
            logger.error("Falha no login - não foi possível confirmar autenticação")
            return False
                
        except requests.exceptions.TooManyRedirects:
            logger.error("Erro: Muitos redirecionamentos. Possível loop de redirecionamento.")
            return False
        except Exception as e:
            logger.error(f"Erro durante login: {str(e)}")
            return False
    
    def _extract_csrf_token(self, soup: BeautifulSoup) -> Optional[str]:
        """Extrai token CSRF da página"""
        # Procurar por diferentes tipos de tokens CSRF
        
        # Método 1: Input hidden
        csrf_input = soup.find('input', {'name': '_csrf'}) or \
                    soup.find('input', {'name': 'csrf_token'}) or \
                    soup.find('input', {'name': 'csrf'})
        
        if csrf_input and csrf_input.get('value'):
            logger.debug(f"CSRF token encontrado em input: {csrf_input.get('value')[:10]}...")
            return csrf_input.get('value')
        
        # Método 2: Meta tag
        csrf_meta = soup.find('meta', {'name': 'csrf-token'}) or \
                    soup.find('meta', {'name': '_csrf'})
        
        if csrf_meta and csrf_meta.get('content'):
            logger.debug(f"CSRF token encontrado em meta: {csrf_meta.get('content')[:10]}...")
            return csrf_meta.get('content')
        
        # Método 3: Script inline (comum em alguns frameworks)
        scripts = soup.find_all('script')
        for script in scripts:
            if script.string:
                # Procurar padrões comuns de CSRF em JavaScript
                csrf_match = re.search(r'["\']_?csrf["\']:\s*["\']([^"\']+)["\']', script.string)
                if csrf_match:
                    logger.debug(f"CSRF token encontrado em script: {csrf_match.group(1)[:10]}...")
                    return csrf_match.group(1)
        
        logger.debug("CSRF token não encontrado na página")
        return None
    
    def _get_csrf_token(self) -> Optional[str]:
        """Obtém token CSRF dos cookies ou meta tags"""
        # Método 1: Cookie
        csrf_cookie = self.session.cookies.get('_csrf')
        if csrf_cookie:
            # Decodificar o cookie se necessário (formato Yii2)
            import urllib.parse
            import base64
            try:
                decoded = urllib.parse.unquote(csrf_cookie)
                if '%3A' in decoded:
                    # Formato serializado do Yii2
                    parts = decoded.split('%3A')
                    if len(parts) >= 4:
                        # O token geralmente está na última parte
                        token = parts[-1].replace('%22', '').replace('%7D', '')
                        if len(token) > 10:
                            return token
                return decoded
            except:
                return csrf_cookie
        
        # Método 2: Buscar na página atual
        try:
            current_url = f"{self.config.base_url}/midias/web/audiencia/index"
            response = self.session.get(current_url, timeout=10)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                return self._extract_csrf_token(soup)
        except:
            pass
        
        return None
    
    def acessar_processo(self, numero_processo: str) -> Optional[BeautifulSoup]:
        """Acessa página do processo com renovação automática de sessão"""
        try:
            # Verificar e renovar sessão se necessário
            if not self._renovar_sessao_se_necessario():
                logger.error("Não foi possível renovar a sessão")
                return None
            
            if not self.validar_processo(numero_processo):
                logger.error(f"Formato inválido do processo: {numero_processo}")
                return None
            
            logger.info(f"Acessando processo: {numero_processo}")
            
            # Construir URL com parâmetros
            url = urljoin(self.config.base_url, self.config.audiencia_endpoint)
            params = {
                'num_processo': numero_processo,
                'tipo_pesquisa': '1'
            }
            
            response = self.session.get(
                url,
                params=params,
                timeout=self.config.timeout
            )
            
            # Verificar se foi redirecionado para login
            if '/login' in response.url:
                logger.warning("Sessão expirada detectada, tentando renovar...")
                if self._renovar_sessao_se_necessario():
                    # Tentar novamente após renovar
                    response = self.session.get(url, params=params, timeout=self.config.timeout)
                else:
                    return None
            
            response.raise_for_status()
            
            # Debug: salvar HTML para análise
            debug_file = f"debug_processo_{numero_processo.replace('.', '_').replace('-', '_')}.html"
            with open(debug_file, 'w', encoding='utf-8') as f:
                f.write(response.text)
            logger.debug(f"HTML salvo em: {debug_file}")
            
            return BeautifulSoup(response.text, 'html.parser')
            
        except Exception as e:
            logger.error(f"Erro ao acessar processo {numero_processo}: {str(e)}")
            return None
    
    def extrair_informacoes_audiencia(self, soup: BeautifulSoup, numero_processo: str) -> List[Dict]:
        """Extrai informações das audiências do processo"""
        audiencias = []
        
        try:
            # Encontrar tabela de audiências - correção do seletor
            # A classe é "table table-striped com-audiencia" (múltiplas classes)
            tabela = soup.find('table', class_='table table-striped com-audiencia')
            
            if not tabela:
                # Tentar com seletor alternativo
                tabela = soup.find('table', {'class': lambda x: x and 'com-audiencia' in x})
            
            if not tabela:
                logger.warning(f"Tabela de audiências não encontrada para processo {numero_processo}")
                # Debug: listar todas as tabelas encontradas
                todas_tabelas = soup.find_all('table')
                logger.debug(f"Total de tabelas encontradas: {len(todas_tabelas)}")
                for i, tab in enumerate(todas_tabelas):
                    logger.debug(f"Tabela {i}: classes={tab.get('class')}")
                return audiencias
            
            logger.debug("Tabela de audiências encontrada")
            
            # Processar cada linha da tabela
            tbody = tabela.find('tbody')
            if tbody:
                linhas = tbody.find_all('tr')
                logger.debug(f"Total de linhas encontradas: {len(linhas)}")
                
                for tr in linhas:
                    try:
                        tds = tr.find_all('td')
                        if len(tds) >= 6:  # Garantir que tem pelo menos 6 colunas
                            audiencia_info = {
                                'id_audiencia': tr.get('id-audiencia', ''),
                                'data': tds[0].text.strip() if tds[0] else '',
                                'tipo': tds[1].text.strip() if tds[1] else '',
                                'juiz': tds[2].text.strip() if tds[2] else '',
                                'descricao': tds[3].text.strip() if tds[3] else '',
                                'status': tds[4].text.strip() if tds[4] else '',
                            }
                            
                            # Verificar se há mídia disponível
                            if tds[5] and tds[5].find('i', class_='fa-video-camera'):
                                audiencia_info['tem_video'] = True
                                audiencias.append(audiencia_info)
                                logger.debug(f"Audiência com vídeo encontrada: {audiencia_info['data']} - {audiencia_info['tipo']}")
                            
                    except Exception as e:
                        logger.error(f"Erro ao processar linha da tabela: {str(e)}")
                        continue
            else:
                logger.warning("Tbody não encontrado na tabela")
            
            logger.info(f"Encontradas {len(audiencias)} audiências com vídeo para processo {numero_processo}")
            return audiencias
            
        except Exception as e:
            logger.error(f"Erro ao extrair informações de audiência: {str(e)}")
            return audiencias
    
    def acessar_detalhes_audiencia(self, numero_processo: str, id_audiencia: str) -> Optional[BeautifulSoup]:
        """Acessa detalhes de uma audiência específica"""
        try:
            # Verificar e renovar sessão se necessário
            if not self._renovar_sessao_se_necessario():
                return None

            # O ID já vem codificado, não precisa codificar novamente
            # Remover qualquer codificação dupla
            id_limpo = id_audiencia.replace('%2C', ',')

            # URL para visualizar audiência
            url = f"{self.config.base_url}/midias/web/audiencia/visualizar"

            logger.info(f"Acessando detalhes da audiência: {url}?id={id_limpo[:20]}...")

            # Construir URL completa manualmente para evitar codificação dupla
            full_url = f"{url}?id={id_limpo}"

            response = self.session.get(
                full_url,
                timeout=self.config.timeout,
                headers={
                    'Referer': f"{self.config.base_url}/midias/web/audiencia/index?num_processo={numero_processo}&tipo_pesquisa=1"
                }
            )

            # Verificar redirecionamento para login
            if '/login' in response.url:
                if self._renovar_sessao_se_necessario():
                    response = self.session.get(full_url, timeout=self.config.timeout)
                else:
                    return None

            response.raise_for_status()

            # Debug: salvar HTML para análise
            debug_file = f"debug_audiencia_{numero_processo.replace('.', '_').replace('-', '_')}.html"
            with open(debug_file, 'w', encoding='utf-8') as f:
                f.write(response.text)
            logger.debug(f"HTML da audiência salvo em: {debug_file}")

            return BeautifulSoup(response.text, 'html.parser')

        except Exception as e:
            logger.error(f"Erro ao acessar detalhes da audiência: {str(e)}")
            return None

    def gerar_chave_acesso(self, seq_audiencia: str, referrer_url: str = None) -> Optional[Dict]:
        """Gera chave de acesso externo para audiência"""
        try:
            # Verificar e renovar sessão se necessário
            if not self._renovar_sessao_se_necessario():
                return None
            
            logger.info(f"Gerando chave de acesso para audiência {seq_audiencia}")
            
            # URL correta baseada no fetch observado
            url = f"{self.config.base_url}/midias/web/audiencia/gerar-chave"
            
            # Obter CSRF token
            csrf_token = self._get_csrf_token()
            if not csrf_token:
                logger.warning("CSRF token não encontrado, tentando sem ele")
            
            # Headers específicos baseados no fetch observado
            headers = {
                'Accept': '*/*',
                'Accept-Language': 'pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7',
                'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
                'X-Requested-With': 'XMLHttpRequest',
                'Sec-Fetch-Dest': 'empty',
                'Sec-Fetch-Mode': 'cors',
                'Sec-Fetch-Site': 'same-origin',
                'Priority': 'u=1, i'
            }
            
            # Adicionar CSRF token se disponível
            if csrf_token:
                headers['X-CSRF-Token'] = csrf_token
            
            # Adicionar Referer se fornecido
            if referrer_url:
                headers['Referer'] = referrer_url
            
            # Dados do formulário - usar o formato exato do fetch observado
            data = f"SEQ_AUDIENCIA={seq_audiencia}"
            
            logger.debug(f"Enviando POST para {url} com dados: {data}")
            
            response = self.session.post(
                url, 
                data=data, 
                headers=headers,
                timeout=self.config.timeout
            )
            
            logger.debug(f"Status da resposta: {response.status_code}")
            logger.debug(f"Headers da resposta: {dict(response.headers)}")
            logger.debug(f"Conteúdo da resposta: {response.text}")
            
            # Verificar redirecionamento para login
            if response.status_code == 401 or '/login' in response.url:
                logger.warning("Sessão expirada durante geração de chave, tentando renovar...")
                if self._renovar_sessao_se_necessario():
                    response = self.session.post(url, data=data, headers=headers, timeout=self.config.timeout)
                else:
                    return None
            
            # Verificar se a resposta foi bem-sucedida (200 ou 201)
            if response.status_code in [200, 201]:
                # A resposta do /gerar-chave retorna HTML da tabela atualizada
                # Vamos extrair a chave diretamente dessa resposta
                try:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    links = self._extrair_links_da_tabela(soup)
                    
                    if links:
                        # Pegar a primeira chave (deve ser a recém-criada)
                        chave_info = links[0]
                        logger.info(f"Chave gerada e extraída: {chave_info.get('chave')}")
                        
                        return {
                            'id': chave_info.get('id', 'novo'),
                            'chave': chave_info.get('chave'),
                            'link': chave_info.get('link'),
                            'ativo': 'Sim',
                            'tipo': 'externo_gerado'
                        }
                    else:
                        # Se não conseguiu extrair da resposta, tentar como antes
                        logger.debug("Não foi possível extrair chave da resposta, tentando carregar via API...")
                        
                        # Aguardar um pouco para o sistema processar
                        time.sleep(0.5)
                        
                        # Carregar a lista de chaves para obter a nova chave
                        links_existentes = self.carregar_links_existentes(seq_audiencia, referrer_url)
                        
                        if links_existentes:
                            # Pegar a chave mais recente (primeira da lista)
                            chave_info = links_existentes[0]
                            logger.info(f"Nova chave obtida via API: {chave_info.get('chave')}")
                            return {
                                'id': chave_info.get('id', 'novo'),
                                'chave': chave_info.get('chave'),
                                'link': chave_info.get('link'),
                                'ativo': 'Sim',
                                'tipo': 'externo_gerado'
                            }
                        else:
                            logger.warning("Chave foi gerada mas não foi possível recuperá-la")
                            
                except Exception as parse_error:
                    logger.error(f"Erro ao processar resposta HTML: {str(parse_error)}")
                    
                    # Fallback: tentar extrair chave usando regex
                    # Procurar por padrões de chave na resposta
                    chave_match = re.search(r'<td>([a-zA-Z0-9]{20})</td>', response.text)
                    if chave_match:
                        chave = chave_match.group(1)
                        link_externo = f"https://midias.pje.jus.br/midias/web/site/login/?chave={chave}"
                        
                        logger.info(f"Chave extraída via regex: {chave}")
                        
                        return {
                            'id': 'novo',
                            'chave': chave,
                            'link': link_externo,
                            'ativo': 'Sim',
                            'tipo': 'externo_gerado'
                        }
                    else:
                        logger.warning("Não foi possível extrair chave da resposta")
            
            logger.error(f"Falha ao gerar chave. Status: {response.status_code}, Resposta: {response.text}")
            return None
            
        except Exception as e:
            logger.error(f"Erro ao gerar chave de acesso: {str(e)}")
            return None
    
    def carregar_links_existentes(self, seq_audiencia: str, referrer_url: str = None) -> List[Dict]:
        """Carrega links de acesso externo existentes"""
        try:
            # URL baseada no segundo fetch observado
            url = f"{self.config.base_url}/midias/web/permissao-audiencia/externo"
            params = {'id_audiencia': seq_audiencia}
            
            # Headers específicos
            headers = {
                'Accept': '*/*',
                'Accept-Language': 'pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7',
                'X-Requested-With': 'XMLHttpRequest',
                'Sec-Fetch-Dest': 'empty',
                'Sec-Fetch-Mode': 'cors',
                'Sec-Fetch-Site': 'same-origin',
                'Priority': 'u=1, i'
            }
            
            # Adicionar CSRF token se disponível
            csrf_token = self._get_csrf_token()
            if csrf_token:
                headers['X-CSRF-Token'] = csrf_token
            
            # Adicionar Referer se fornecido
            if referrer_url:
                headers['Referer'] = referrer_url
            
            logger.debug(f"Carregando links existentes para audiência {seq_audiencia}")
            
            response = self.session.get(url, params=params, headers=headers, timeout=self.config.timeout)
            
            logger.debug(f"Status resposta carregar links: {response.status_code}")
            logger.debug(f"Conteúdo resposta carregar links: {response.text[:500]}")
            
            if response.status_code == 200:
                # Processar resposta HTML
                soup = BeautifulSoup(response.text, 'html.parser')
                return self._extrair_links_da_tabela(soup)
            
            return []
            
        except Exception as e:
            logger.error(f"Erro ao carregar links existentes: {str(e)}")
            return []
    
    def _extrair_links_da_tabela(self, soup: BeautifulSoup) -> List[Dict]:
        """Extrai links da tabela HTML"""
        links = []
        try:
            # Procurar pela tabela dentro da div acesso-externo
            tabela = soup.find('table', class_='table')
            
            if not tabela:
                logger.debug("Tabela não encontrada")
                return links
            
            tbody = tabela.find('tbody')
            if not tbody:
                logger.debug("Tbody não encontrado - tabela pode estar vazia")
                return links
            
            # Processar cada linha da tabela
            for tr in tbody.find_all('tr'):
                try:
                    # Extrair dados das colunas: #, Chave, Link, Ativo, Ação
                    cols = tr.find_all(['th', 'td'])
                    
                    if len(cols) >= 4:
                        # Coluna 0: # (número)
                        numero = cols[0].text.strip()
                        
                        # Coluna 1: Chave
                        chave = cols[1].text.strip()
                        
                        # Coluna 2: Link (contém o botão com onclick)
                        link_col = cols[2]
                        
                        # Coluna 3: Ativo
                        ativo = cols[3].text.strip()
                        
                        if chave and ativo.lower() == 'sim':
                            # Construir link completo
                            link_externo = f"https://midias.pje.jus.br/midias/web/site/login/?chave={chave}"
                            
                            link_info = {
                                'id': numero,
                                'chave': chave,
                                'link': link_externo,
                                'ativo': ativo,
                                'tipo': 'externo'
                            }
                            
                            links.append(link_info)
                            logger.debug(f"Link extraído: ID={numero}, Chave={chave}")
                
                except Exception as e:
                    logger.error(f"Erro ao processar linha da tabela: {str(e)}")
                    continue
            
            logger.info(f"Extraídos {len(links)} links da tabela")
            return links
            
        except Exception as e:
            logger.error(f"Erro ao extrair links da tabela: {str(e)}")
            return links
    
    def extrair_links_midia(self, soup: BeautifulSoup, numero_processo: str) -> List[Dict]:
        """Extrai links de mídia da página"""
        links = []
        
        try:
            # Primeiro, procurar por links existentes na tabela
            tabelas = soup.find_all('table', class_='table')
            
            for tabela in tabelas:
                thead = tabela.find('thead')
                if thead and 'Chave' in thead.text and 'Link' in thead.text:
                    logger.debug("Tabela de acesso externo encontrada")
                    links.extend(self._extrair_links_da_tabela(soup))
            
            # Extrair informações adicionais da audiência
            info_divs = soup.find_all('div', class_='col-md-6')
            info_adicional = {}
            
            for div in info_divs:
                texto = div.text.strip()
                if ':' in texto:
                    chave, valor = texto.split(':', 1)
                    info_adicional[chave.strip()] = valor.strip()
            
            # Procurar por botão "Gerar chave" com diferentes seletores
            btn_gerar = None
            seq_audiencia = None
            
            # Método 1: ID exato
            btn_gerar = soup.find('button', id='btn-acesso-externo')
            
            # Método 2: Classe
            if not btn_gerar:
                btn_gerar = soup.find('button', class_='btn-acesso-externo')
            
            # Método 3: Texto do botão
            if not btn_gerar:
                btn_gerar = soup.find('button', string=re.compile(r'Gerar\s+chave', re.I))
            
            # Método 4: Procurar em qualquer elemento que contenha "Gerar chave"
            if not btn_gerar:
                elementos = soup.find_all(string=re.compile(r'Gerar\s+chave', re.I))
                for elemento in elementos:
                    parent = elemento.parent
                    if parent and parent.name == 'button':
                        btn_gerar = parent
                        break
                    # Verificar se é dentro de um botão
                    btn_ancestor = parent.find_parent('button') if parent else None
                    if btn_ancestor:
                        btn_gerar = btn_ancestor
                        break
            
            # Método 5: Procurar qualquer botão que contenha "chave" no onclick ou atributos
            if not btn_gerar:
                botoes = soup.find_all('button')
                for botao in botoes:
                    onclick = botao.get('onclick', '')
                    if 'chave' in onclick.lower() or 'gerar' in onclick.lower():
                        btn_gerar = botao
                        break
            
            if btn_gerar:
                # Tentar extrair seq-audiencia de diferentes formas
                seq_audiencia = btn_gerar.get('seq-audiencia')
                
                if not seq_audiencia:
                    # Tentar outros atributos
                    seq_audiencia = btn_gerar.get('data-seq-audiencia') or \
                                  btn_gerar.get('data-audiencia') or \
                                  btn_gerar.get('audiencia-id')
                
                if not seq_audiencia:
                    # Procurar no onclick
                    onclick = btn_gerar.get('onclick', '')
                    seq_match = re.search(r'(\d+)', onclick)
                    if seq_match:
                        seq_audiencia = seq_match.group(1)
                
                if not seq_audiencia:
                    # Procurar em elementos próximos
                    parent = btn_gerar.parent
                    if parent:
                        # Procurar inputs hidden próximos
                        hidden_inputs = parent.find_all('input', type='hidden')
                        for inp in hidden_inputs:
                            if 'audiencia' in inp.get('name', '').lower():
                                seq_audiencia = inp.get('value')
                                break
                
                logger.debug(f"Botão gerar chave encontrado com seq-audiencia: {seq_audiencia}")
            else:
                logger.debug("Botão 'Gerar chave' não encontrado")
                
                # Debug: mostrar todo o HTML da área de acesso externo
                acesso_div = soup.find('div', class_='acesso-externo')
                if acesso_div:
                    logger.debug(f"Conteúdo da div acesso-externo: {acesso_div.get_text()[:200]}")
                
                # Procurar qualquer referência a seq-audiencia no HTML
                html_str = str(soup)
                seq_matches = re.findall(r'seq-audiencia["\']?\s*[:=]\s*["\']?(\d+)', html_str, re.I)
                if seq_matches:
                    seq_audiencia = seq_matches[0]
                    logger.debug(f"seq-audiencia encontrado via regex: {seq_audiencia}")
            
            # Se não houver links ativos e temos seq_audiencia, tentar gerar
            if not links and seq_audiencia:
                logger.info(f"Nenhum link ativo encontrado. Tentando gerar chave para audiência {seq_audiencia}")
                
                # Construir URL de referência para o Referer
                referrer_url = f"{self.config.base_url}/midias/web/{numero_processo}"
                
                # Primeiro, tentar carregar links existentes
                links_existentes = self.carregar_links_existentes(seq_audiencia, referrer_url)
                if links_existentes:
                    logger.info(f"Encontrados {len(links_existentes)} links existentes")
                    links.extend(links_existentes)
                else:
                    # Se não há links existentes, gerar novo
                    chave_info = self.gerar_chave_acesso(seq_audiencia, referrer_url)
                    if chave_info:
                        links.append(chave_info)
                        logger.info("Nova chave gerada com sucesso")
                    else:
                        logger.warning("Falha ao gerar nova chave")
            elif not seq_audiencia:
                logger.warning("seq-audiencia não encontrado, não é possível gerar chave")
            
            # Adicionar informações extras aos links
            for link in links:
                link.update({
                    'sincronizado_por': info_adicional.get('Sicronizado por', ''),
                    'tipo_audiencia': info_adicional.get('Tipo de audiência', ''),
                    'juiz': info_adicional.get('Juiz', ''),
                    'data_audiencia': info_adicional.get('Data da audiência', ''),
                    'sala': info_adicional.get('Sala', ''),
                    'tribunal': info_adicional.get('Tribunal', ''),
                    'unidade': info_adicional.get('Unidade judiciária', '')
                })
            
            # Extrair link direto do vídeo (se disponível)
            player_div = soup.find('div', id='player-wrapper')
            if player_div and player_div.get('data-src'):
                video_url = player_div['data-src']
                links.append({
                    'id': 'video_direto',
                    'chave': 'N/A',
                    'link': video_url,
                    'ativo': 'Sim',
                    'tipo': 'video_direto',
                    **info_adicional
                })
                logger.info("Link direto do vídeo encontrado")
            
            logger.info(f"Extraídos {len(links)} links para processo {numero_processo}")
            return links
            
        except Exception as e:
            logger.error(f"Erro ao extrair links de mídia: {str(e)}")
            return links
    
    def processar_multiplos_processos(self, numeros_processos: List[str]) -> Dict[str, ProcessoInfo]:
        """Processa múltiplos processos"""
        resultados = {}

        for i, numero_processo in enumerate(numeros_processos, 1):
            try:
                logger.info(f"Processando {i}/{len(numeros_processos)}: {numero_processo}")

                # Acessar processo
                soup = self.acessar_processo(numero_processo)
                if not soup:
                    continue
                
                # Criar objeto ProcessoInfo
                processo_info = ProcessoInfo(numero=numero_processo)

                # Extrair informações de audiências
                audiencias = self.extrair_informacoes_audiencia(soup, numero_processo)

                # Se houver audiências, acessar a página do processo diretamente
                if audiencias:
                    # URL direta do processo (como no link do HTML)
                    url_processo = f"{self.config.base_url}/midias/web/{numero_processo}"

                    logger.info(f"Acessando página do processo: {url_processo}")

                    response = self.session.get(url_processo, timeout=self.config.timeout)

                    if response.status_code == 200:
                        soup_detalhes = BeautifulSoup(response.text, 'html.parser')
                        links = self.extrair_links_midia(soup_detalhes, numero_processo)

                        # Se temos múltiplas audiências mas só uma página de detalhes,
                        # assumir que os links são para a primeira audiência (ou todas)
                        for link in links:
                            # Pegar informações da primeira audiência
                            if audiencias:
                                audiencia = audiencias[0]
                                # Preservar informações já extraídas, mas adicionar da audiência se não existirem
                                if not link.get('data_audiencia'):
                                    link['data_audiencia'] = audiencia.get('data')
                                if not link.get('tipo_audiencia'):
                                    link['tipo_audiencia'] = audiencia.get('tipo')
                                if not link.get('juiz'):
                                    link['juiz'] = audiencia.get('juiz')
                                link['status'] = audiencia.get('status')

                        processo_info.links_midia.extend(links)
                    else:
                        logger.warning(f"Não foi possível acessar detalhes do processo: {response.status_code}")

                # Adicionar ao resultado
                resultados[numero_processo] = processo_info
                self.processos_info[numero_processo] = processo_info

                # Delay entre requisições
                time.sleep(self.config.delay_between_requests)

            except Exception as e:
                logger.error(f"Erro ao processar {numero_processo}: {str(e)}")
                continue
            
        return resultados

    def salvar_resultados(self, formato: str = 'json') -> str:
        """Salva resultados em arquivo"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        if formato == 'json':
            filename = f"{self.config.output_dir}/resultados_{timestamp}.json"
            
            # Converter dataclasses para dict
            data = {}
            for num_proc, info in self.processos_info.items():
                data[num_proc] = {
                    'numero': info.numero,
                    'links_midia': info.links_midia
                }
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        
        elif formato == 'txt':
            filename = f"{self.config.output_dir}/resultados_{timestamp}.txt"
            
            with open(filename, 'w', encoding='utf-8') as f:
                for num_proc, info in self.processos_info.items():
                    f.write(f"\n{'='*80}\n")
                    f.write(f"PROCESSO: {num_proc}\n")
                    f.write(f"{'='*80}\n\n")
                    
                    if info.links_midia:
                        for i, link in enumerate(info.links_midia, 1):
                            f.write(f"Link {i}:\n")
                            f.write(f"  URL: {link.get('link', 'N/A')}\n")
                            f.write(f"  Chave: {link.get('chave', 'N/A')}\n")
                            f.write(f"  Tipo: {link.get('tipo', 'N/A')}\n")
                            if link.get('descricao'):
                                f.write(f"  Descrição: {link.get('descricao')}\n")
                            if link.get('data_audiencia'):
                                f.write(f"  Data Audiência: {link.get('data_audiencia')}\n")
                            if link.get('tipo_audiencia'):
                                f.write(f"  Tipo Audiência: {link.get('tipo_audiencia')}\n")
                            if link.get('juiz'):
                                f.write(f"  Juiz: {link.get('juiz')}\n")
                            if link.get('tribunal'):
                                f.write(f"  Tribunal: {link.get('tribunal')}\n")
                            if link.get('sala'):
                                f.write(f"  Sala: {link.get('sala')}\n")
                            f.write("\n")
                    else:
                        f.write("  Nenhum link de mídia encontrado.\n")
        
        logger.info(f"Resultados salvos em: {filename}")
        return filename
    
    def executar(self, cpf: str, senha: str, numeros_processos: List[str]) -> bool:
        """Executa todo o fluxo de automação"""
        try:
            logger.info(f"Iniciando automação para {len(numeros_processos)} processos")
            
            # Passo 1: Login
            if not self.login(cpf, senha):
                logger.error("Falha no login. Abortando operação.")
                return False
            
            # Passo 2-4: Processar cada processo
            resultados = self.processar_multiplos_processos(numeros_processos)
            
            # Salvar resultados
            if resultados:
                self.salvar_resultados('json')
                self.salvar_resultados('txt')
                
                logger.info(f"Automação concluída. Processados {len(resultados)} processos.")
                return True
            else:
                logger.warning("Nenhum resultado obtido.")
                return False
                
        except Exception as e:
            logger.error(f"Erro durante execução: {str(e)}")
            return False
    
    def limpar_sessoes_antigas(self):
        """Remove arquivos de sessão expirados"""
        try:
            session_dir = Path(self.config.session_dir)
            if not session_dir.exists():
                return
            
            for session_file in session_dir.glob("session_*.pkl"):
                try:
                    with open(session_file, 'rb') as f:
                        session_info: SessionInfo = pickle.load(f)
                    
                    idade = datetime.now() - session_info.created_at
                    if idade > timedelta(hours=self.config.session_lifetime_hours):
                        session_file.unlink()
                        logger.debug(f"Sessão expirada removida: {session_file.name}")
                        
                except Exception as e:
                    logger.error(f"Erro ao verificar sessão {session_file.name}: {str(e)}")
                    
        except Exception as e:
            logger.error(f"Erro ao limpar sessões antigas: {str(e)}")

def criar_arquivos_exemplo():
    """Cria arquivos de exemplo se não existirem"""
    from pathlib import Path
    
    # Criar .env de exemplo
    if not Path('.env').exists():
        with open('.env.example', 'w', encoding='utf-8') as f:
            f.write("""# Copie este arquivo para .env e preencha com suas credenciais
PJE_CPF=12345678901
PJE_SENHA=sua_senha_aqui
""")
        print("📄 Arquivo '.env.example' criado. Copie para '.env' e preencha suas credenciais.")
    
    # Criar processos.txt de exemplo
    if not Path('processos.txt').exists():
        with open('processos.txt.example', 'w', encoding='utf-8') as f:
            f.write("""# Lista de processos para processar
# Um número de processo por linha
# Linhas começando com # são ignoradas

8001011-70.2025.8.05.0216
1234567-89.2025.1.23.4567
9876543-21.2025.9.87.6543
""")
        print("📄 Arquivo 'processos.txt.example' criado. Copie para 'processos.txt' e adicione seus processos.")
    
    # Criar config.yaml de exemplo
    if not Path('config.yaml').exists():
        with open('config.yaml', 'w', encoding='utf-8') as f:
            f.write("""pje:
  base_url: "https://midias.pje.jus.br"
  login_endpoint: "/midias/web/site/login"
  audiencia_endpoint: "/midias/web/audiencia/index"
  max_retries: 3
  timeout: 30
  delay_between_requests: 1.0
  output_dir: "downloads"
  session_dir: ".sessions"
  session_lifetime_hours: 8
""")
        print("📄 Arquivo 'config.yaml' criado com configurações padrão.")

def main():
    """Função principal"""
    from pathlib import Path
    
    # Criar arquivos de exemplo se necessário
    criar_arquivos_exemplo()
    
    # Carregar variáveis de ambiente
    load_dotenv()
    
    # Configurações
    config = Config()
    
    # Criar instância da automação
    automation = PJEAutomation(config)
    
    # Limpar sessões antigas
    automation.limpar_sessoes_antigas()
    
    # Verificar credenciais no .env
    cpf = os.getenv('PJE_CPF')
    senha = os.getenv('PJE_SENHA')
    
    if cpf and senha:
        print("✅ Credenciais encontradas no arquivo .env")
        print(f"CPF: {cpf[:3]}***{cpf[-3:]}")
    else:
        print("⚠️  Credenciais não encontradas no .env")
        cpf = input("Digite o CPF: ")
        senha = input("Digite a senha: ")
    
    # Verificar arquivo de processos
    processos = []
    processos_file = "processos.txt"
    
    if Path(processos_file).exists():
        print(f"\n✅ Arquivo '{processos_file}' encontrado")
        
        # Carregar processos do arquivo
        with open(processos_file, 'r', encoding='utf-8') as f:
            for linha in f:
                processo = linha.strip()
                if processo and not processo.startswith('#'):
                    if automation.validar_processo(processo):
                        processos.append(processo)
                    else:
                        print(f"⚠️  Processo inválido ignorado: {processo}")
        
        if processos:
            print(f"📋 {len(processos)} processos válidos carregados do arquivo")
            print("\nProcessos a serem processados:")
            for i, proc in enumerate(processos, 1):
                print(f"  {i}. {proc}")
            
            # Perguntar se deseja continuar ou adicionar mais
            resposta = input("\nDeseja (C)ontinuar com estes processos ou (A)dicionar mais? [C/a]: ").strip().lower()
            
            if resposta == 'a':
                print("\nAdicione mais processos (linha vazia para finalizar):")
                while True:
                    processo = input().strip()
                    if not processo:
                        break
                    if automation.validar_processo(processo):
                        processos.append(processo)
                        print(f"✅ Processo adicionado: {processo}")
                    else:
                        print(f"❌ Formato inválido: {processo}. Use o formato XXXXXXX-XX.XXXX.X.XX.XXXX")
        else:
            print("⚠️  Nenhum processo válido encontrado no arquivo")
    else:
        print(f"\n⚠️  Arquivo '{processos_file}' não encontrado")
    
    # Se ainda não há processos, solicitar entrada manual
    if not processos:
        print("\nDigite os números dos processos (um por linha, linha vazia para finalizar):")
        while True:
            processo = input().strip()
            if not processo:
                break
            if automation.validar_processo(processo):
                processos.append(processo)
                print(f"✅ Processo adicionado: {processo}")
            else:
                print(f"❌ Formato inválido: {processo}. Use o formato XXXXXXX-XX.XXXX.X.XX.XXXX")
    
    if not processos:
        print("\n❌ Nenhum processo válido informado.")
        return
    
    # Resumo antes de executar
    print(f"\n{'='*50}")
    print("📋 RESUMO DA EXECUÇÃO")
    print(f"{'='*50}")
    print(f"Total de processos: {len(processos)}")
    print(f"Diretório de saída: {config.output_dir}/")
    print(f"Delay entre requisições: {config.delay_between_requests}s")
    print(f"Sessões salvas em: {config.session_dir}/")
    print(f"{'='*50}")
    
    # Confirmar execução
    confirmar = input("\nDeseja iniciar o processamento? [S/n]: ").strip().lower()
    if confirmar == 'n':
        print("❌ Operação cancelada pelo usuário")
        return
    
    # Executar automação
    print("\n🚀 Iniciando automação...")
    sucesso = automation.executar(cpf, senha, processos)
    
    if sucesso:
        print("\n✅ Automação concluída com sucesso!")
        print(f"📁 Resultados salvos em: {config.output_dir}/")
        
        # Mostrar arquivos criados
        output_path = Path(config.output_dir)
        if output_path.exists():
            arquivos = list(output_path.glob("resultados_*.json")) + list(output_path.glob("resultados_*.txt"))
            if arquivos:
                print("\n📄 Arquivos gerados:")
                for arquivo in sorted(arquivos)[-4:]:  # Mostrar os 4 mais recentes
                    print(f"  - {arquivo.name}")
    else:
        print("\n❌ Erro durante a automação. Verifique os logs em 'pje_automation.log'")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Operação interrompida pelo usuário")
    except Exception as e:
        print(f"\n❌ Erro não tratado: {str(e)}")
        logger.exception("Erro não tratado na função main")