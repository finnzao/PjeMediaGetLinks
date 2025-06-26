#!/usr/bin/env python3
"""
Script CLI avançado para automação PJE com suporte assíncrono
"""

import asyncio
import aiohttp
import argparse
import os
import sys
from pathlib import Path
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor
import yaml
from dotenv import load_dotenv
from datetime import datetime
import csv

# Importar a classe principal
from pje_automation import PJEAutomation, Config, logger

class AsyncPJEAutomation(PJEAutomation):
    """Versão assíncrona da automação PJE"""
    
    def __init__(self, config: Config = None, max_concurrent: int = 5):
        super().__init__(config)
        self.max_concurrent = max_concurrent
        self.semaphore = asyncio.Semaphore(max_concurrent)
    
    async def processar_processo_async(self, session: aiohttp.ClientSession, numero_processo: str) -> Optional[Dict]:
        """Processa um processo de forma assíncrona"""
        async with self.semaphore:
            try:
                logger.info(f"Processando processo: {numero_processo}")
                
                # Validar formato
                if not self.validar_processo(numero_processo):
                    logger.error(f"Formato inválido: {numero_processo}")
                    return None
                
                # Acessar processo
                url = f"{self.config.base_url}{self.config.audiencia_endpoint}"
                params = {
                    'num_processo': numero_processo,
                    'tipo_pesquisa': '1'
                }
                
                async with session.get(url, params=params) as response:
                    if response.status == 200:
                        html = await response.text()
                        # Processar HTML em thread separada
                        loop = asyncio.get_event_loop()
                        with ThreadPoolExecutor() as executor:
                            result = await loop.run_in_executor(
                                executor,
                                self._processar_html_processo,
                                html,
                                numero_processo
                            )
                        return result
                    else:
                        logger.error(f"Erro ao acessar processo {numero_processo}: Status {response.status}")
                        return None
                        
            except Exception as e:
                logger.error(f"Erro ao processar {numero_processo}: {str(e)}")
                return None
    
    def _processar_html_processo(self, html: str, numero_processo: str) -> Dict:
        """Processa HTML do processo (executado em thread)"""
        from bs4 import BeautifulSoup
        
        soup = BeautifulSoup(html, 'html.parser')
        audiencias = self.extrair_informacoes_audiencia(soup, numero_processo)
        
        return {
            'numero': numero_processo,
            'audiencias': audiencias,
            'links_midia': []
        }
    
    async def executar_async(self, cpf: str, senha: str, numeros_processos: List[str]) -> bool:
        """Executa automação de forma assíncrona"""
        try:
            # Login síncrono (geralmente precisa manter sessão)
            if not self.login(cpf, senha):
                logger.error("Falha no login")
                return False
            
            # Criar sessão aiohttp com cookies da sessão requests
            cookies = self.session.cookies.get_dict()
            
            async with aiohttp.ClientSession(
                headers=self.config.headers,
                cookies=cookies,
                connector=aiohttp.TCPConnector(limit=self.max_concurrent)
            ) as session:
                
                # Processar todos os processos de forma assíncrona
                tasks = []
                for numero_processo in numeros_processos:
                    task = self.processar_processo_async(session, numero_processo)
                    tasks.append(task)
                
                # Aguardar conclusão com barra de progresso
                resultados = []
                for i, task in enumerate(asyncio.as_completed(tasks), 1):
                    resultado = await task
                    if resultado:
                        resultados.append(resultado)
                    
                    # Progresso
                    progress = (i / len(tasks)) * 100
                    logger.info(f"Progresso: {progress:.1f}% ({i}/{len(tasks)})")
                
                # Salvar resultados
                if resultados:
                    self._salvar_resultados_async(resultados)
                    return True
                else:
                    logger.warning("Nenhum resultado obtido")
                    return False
                    
        except Exception as e:
            logger.error(f"Erro durante execução assíncrona: {str(e)}")
            return False
    
    def _salvar_resultados_async(self, resultados: List[Dict]):
        """Salva resultados do processamento assíncrono"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # JSON
        json_file = f"{self.config.output_dir}/resultados_async_{timestamp}.json"
        with open(json_file, 'w', encoding='utf-8') as f:
            import json
            json.dump(resultados, f, ensure_ascii=False, indent=2)
        
        # CSV
        csv_file = f"{self.config.output_dir}/resultados_async_{timestamp}.csv"
        with open(csv_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=['processo', 'data', 'tipo', 'juiz', 'status', 'links'])
            writer.writeheader()
            
            for resultado in resultados:
                for audiencia in resultado.get('audiencias', []):
                    writer.writerow({
                        'processo': resultado['numero'],
                        'data': audiencia.get('data', ''),
                        'tipo': audiencia.get('tipo', ''),
                        'juiz': audiencia.get('juiz', ''),
                        'status': audiencia.get('status', ''),
                        'links': len(resultado.get('links_midia', []))
                    })
        
        logger.info(f"Resultados salvos em: {json_file} e {csv_file}")

def load_config(config_file: str = 'config.yaml') -> Config:
    """Carrega configuração de arquivo YAML"""
    if Path(config_file).exists():
        with open(config_file, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
            
        pje_config = data.get('pje', {})
        return Config(**pje_config)
    else:
        return Config()

def load_processos_file(filename: str) -> List[str]:
    """Carrega lista de processos de arquivo"""
    processos = []
    
    with open(filename, 'r', encoding='utf-8') as f:
        for line in f:
            processo = line.strip()
            if processo and not processo.startswith('#'):
                processos.append(processo)
    
    return processos

def create_parser() -> argparse.ArgumentParser:
    """Cria parser de argumentos"""
    parser = argparse.ArgumentParser(
        description='Automação PJE - Captura de Links de Mídia',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos de uso:
  %(prog)s -c 12345678901 -s senha123 -p 8001011-70.2025.8.05.0216
  %(prog)s --file processos.txt --async
  %(prog)s --config custom_config.yaml --output resultados/
        """
    )
    
    # Autenticação
    auth_group = parser.add_argument_group('Autenticação')
    auth_group.add_argument('-c', '--cpf', 
                           help='CPF para login (ou use variável PJE_CPF)')
    auth_group.add_argument('-s', '--senha', 
                           help='Senha para login (ou use variável PJE_SENHA)')
    
    # Processos
    proc_group = parser.add_argument_group('Processos')
    proc_group.add_argument('-p', '--processo', 
                           action='append',
                           help='Número do processo (pode ser usado múltiplas vezes)')
    proc_group.add_argument('-f', '--file', 
                           help='Arquivo com lista de processos')
    
    # Configurações
    config_group = parser.add_argument_group('Configurações')
    config_group.add_argument('--config', 
                             default='config.yaml',
                             help='Arquivo de configuração (padrão: config.yaml)')
    config_group.add_argument('-o', '--output', 
                             help='Diretório de saída')
    config_group.add_argument('--delay', 
                             type=float,
                             help='Delay entre requisições em segundos')
    
    # Modo de execução
    exec_group = parser.add_argument_group('Execução')
    exec_group.add_argument('--async', 
                           action='store_true',
                           help='Usar processamento assíncrono')
    exec_group.add_argument('--max-concurrent', 
                           type=int,
                           default=5,
                           help='Máximo de requisições simultâneas (padrão: 5)')
    
    # Outros
    parser.add_argument('-v', '--verbose', 
                       action='store_true',
                       help='Modo verboso')
    parser.add_argument('--dry-run', 
                       action='store_true',
                       help='Simular execução sem fazer requisições')
    
    return parser

def main():
    """Função principal do CLI"""
    # Carregar variáveis de ambiente
    load_dotenv()
    
    # Parser de argumentos
    parser = create_parser()
    args = parser.parse_args()
    
    # Configurar logging
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    
    # Carregar configuração
    config = load_config(args.config)
    
    # Sobrescrever configurações com argumentos
    if args.output:
        config.output_dir = args.output
    if args.delay:
        config.delay_between_requests = args.delay
    
    # Obter credenciais
    cpf = args.cpf or os.getenv('PJE_CPF')
    senha = args.senha or os.getenv('PJE_SENHA')
    
    if not cpf or not senha:
        print("❌ Erro: CPF e senha são obrigatórios!")
        print("Use -c e -s ou defina PJE_CPF e PJE_SENHA no ambiente")
        sys.exit(1)
    
    # Obter lista de processos
    processos = []
    
    if args.processo:
        processos.extend(args.processo)
    
    if args.file:
        try:
            processos.extend(load_processos_file(args.file))
        except FileNotFoundError:
            print(f"❌ Erro: Arquivo '{args.file}' não encontrado!")
            sys.exit(1)
    
    if not processos:
        print("❌ Erro: Nenhum processo informado!")
        print("Use -p para processos individuais ou -f para arquivo")
        sys.exit(1)
    
    # Validar processos
    automation = PJEAutomation(config)
    processos_validos = []
    
    for processo in processos:
        if automation.validar_processo(processo):
            processos_validos.append(processo)
        else:
            logger.warning(f"Processo inválido ignorado: {processo}")
    
    if not processos_validos:
        print("❌ Erro: Nenhum processo válido encontrado!")
        sys.exit(1)
    
    print(f"\n📋 Processos a serem processados: {len(processos_validos)}")
    
    if args.dry_run:
        print("\n🔍 Modo dry-run - Simulando execução:")
        for i, processo in enumerate(processos_validos, 1):
            print(f"  {i}. {processo}")
        print("\n✅ Simulação concluída")
        sys.exit(0)
    
    # Executar automação
    print("\n🚀 Iniciando automação...")
    
    try:
        if args.async:
            # Execução assíncrona
            async_automation = AsyncPJEAutomation(config, args.max_concurrent)
            sucesso = asyncio.run(
                async_automation.executar_async(cpf, senha, processos_validos)
            )
        else:
            # Execução síncrona
            sucesso = automation.executar(cpf, senha, processos_validos)
        
        if sucesso:
            print(f"\n✅ Automação concluída com sucesso!")
            print(f"📁 Resultados salvos em: {config.output_dir}/")
        else:
            print("\n❌ Erro durante a automação")
            sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n\n⚠️  Automação interrompida pelo usuário")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Erro não tratado: {str(e)}")
        logger.exception("Erro não tratado")
        sys.exit(1)

if __name__ == "__main__":
    main()