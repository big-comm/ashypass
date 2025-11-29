#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Gerador de Senhas Moderno e Completo
Versão: 2.0
Autor: Antigravity AI
"""

import random
import string
import secrets
import sys
import os
from dataclasses import dataclass
from typing import List, Tuple

try:
    from colorama import Fore, Back, Style, init
    init(autoreset=True)
except ImportError:
    print("Instalando dependência colorama...")
    os.system(f"{sys.executable} -m pip install colorama")
    from colorama import Fore, Back, Style, init
    init(autoreset=True)


@dataclass
class PasswordConfig:
    """Configuração para geração de senha"""
    length: int = 16
    use_uppercase: bool = True
    use_lowercase: bool = True
    use_digits: bool = True
    use_symbols: bool = True
    exclude_ambiguous: bool = True
    custom_symbols: str = ""


class PasswordGenerator:
    """Classe principal para geração de senhas"""
    
    # Caracteres ambíguos que podem ser confundidos
    AMBIGUOUS_CHARS = "il1Lo0O"
    
    # Conjunto de símbolos padrão
    DEFAULT_SYMBOLS = "!@#$%&*()-_=+[]{}|;:,.<>?/"
    
    # Lista de palavras para passphrases (palavras comuns em português)
    PASSPHRASE_WORDS = [
        "amor", "arco", "arte", "ativo", "azul", "belo", "bola", "casa", "ceu", "chave",
        "cidade", "claro", "cor", "danca", "dia", "doce", "estrela", "faca", "feliz", "festa",
        "fogo", "folha", "forte", "gato", "grande", "ideia", "jardim", "lago", "lampada", "leao",
        "libro", "limao", "linda", "longe", "lua", "luz", "mae", "manha", "mar", "mesa",
        "monte", "mundo", "musica", "neve", "noite", "novo", "nuvem", "olho", "onda", "ouro",
        "pai", "palavra", "pao", "papel", "paz", "pedra", "peixe", "pequeno", "perto", "planta",
        "poeta", "ponte", "porta", "praia", "prata", "preto", "quadro", "raio", "rapido", "rei",
        "rio", "rocha", "rosa", "rua", "saber", "sabio", "sal", "sangue", "sapo", "segredo",
        "senha", "sereno", "sol", "sonho", "sorte", "suave", "tempo", "terra", "tigre", "torre",
        "trabalho", "trem", "tres", "trigo", "ultimo", "uniao", "vale", "vela", "vento", "verde",
        "vida", "vinho", "violeta", "virar", "visao", "viver", "voo", "voz", "zebra", "zero"
    ]
    
    def __init__(self):
        self.config = PasswordConfig()
    
    def clear_screen(self):
        """Limpa a tela do terminal"""
        os.system('clear' if os.name != 'nt' else 'cls')
    
    def print_header(self):
        """Exibe o cabeçalho do programa"""
        self.clear_screen()
        print(f"\n{Fore.CYAN}{'='*70}")
        print(f"{Fore.YELLOW}{Style.BRIGHT}          🔐 GERADOR DE SENHAS PROFISSIONAL v2.0 🔐")
        print(f"{Fore.CYAN}{'='*70}{Style.RESET_ALL}\n")
    
    def print_menu(self):
        """Exibe o menu principal"""
        print(f"{Fore.GREEN}{Style.BRIGHT}MENU PRINCIPAL:{Style.RESET_ALL}")
        print(f"{Fore.WHITE}  1. {Fore.CYAN}Gerar Senha Rápida (Padrão)")
        print(f"{Fore.WHITE}  2. {Fore.CYAN}Gerar Senha Personalizada")
        print(f"{Fore.WHITE}  3. {Fore.CYAN}Gerar Passphrase (Fácil de Memorizar)")
        print(f"{Fore.WHITE}  4. {Fore.CYAN}Gerar PIN Numérico")
        print(f"{Fore.WHITE}  5. {Fore.CYAN}Gerar Múltiplas Senhas")
        print(f"{Fore.WHITE}  6. {Fore.CYAN}Verificar Força de Senha")
        print(f"{Fore.WHITE}  7. {Fore.CYAN}Configurações")
        print(f"{Fore.WHITE}  0. {Fore.RED}Sair{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'─'*70}{Style.RESET_ALL}")
    
    def generate_password(self, config: PasswordConfig = None) -> str:
        """Gera uma senha baseada na configuração"""
        if config is None:
            config = self.config
        
        # Constrói o conjunto de caracteres
        chars = ""
        
        if config.use_lowercase:
            chars += string.ascii_lowercase
        if config.use_uppercase:
            chars += string.ascii_uppercase
        if config.use_digits:
            chars += string.digits
        if config.use_symbols:
            if config.custom_symbols:
                chars += config.custom_symbols
            else:
                chars += self.DEFAULT_SYMBOLS
        
        # Remove caracteres ambíguos se necessário
        if config.exclude_ambiguous:
            chars = ''.join(c for c in chars if c not in self.AMBIGUOUS_CHARS)
        
        if not chars:
            raise ValueError("Não há caracteres disponíveis para gerar a senha!")
        
        # Usa secrets para geração criptograficamente segura
        password = ''.join(secrets.choice(chars) for _ in range(config.length))
        
        # Garante que a senha tenha pelo menos um caractere de cada tipo selecionado
        password = self._ensure_complexity(password, config, chars)
        
        return password
    
    def _ensure_complexity(self, password: str, config: PasswordConfig, chars: str) -> str:
        """Garante que a senha tenha pelo menos um caractere de cada tipo selecionado"""
        password_list = list(password)
        
        # Verifica e adiciona caracteres faltantes
        if config.use_lowercase and not any(c in string.ascii_lowercase for c in password):
            password_list[secrets.randbelow(len(password_list))] = secrets.choice(string.ascii_lowercase)
        
        if config.use_uppercase and not any(c in string.ascii_uppercase for c in password):
            password_list[secrets.randbelow(len(password_list))] = secrets.choice(string.ascii_uppercase)
        
        if config.use_digits and not any(c in string.digits for c in password):
            password_list[secrets.randbelow(len(password_list))] = secrets.choice(string.digits)
        
        if config.use_symbols:
            symbols = config.custom_symbols if config.custom_symbols else self.DEFAULT_SYMBOLS
            if config.exclude_ambiguous:
                symbols = ''.join(c for c in symbols if c not in self.AMBIGUOUS_CHARS)
            if not any(c in symbols for c in password):
                password_list[secrets.randbelow(len(password_list))] = secrets.choice(symbols)
        
        return ''.join(password_list)
    
    def generate_passphrase(self, num_words: int = 4, separator: str = "-", 
                          capitalize: bool = True, add_number: bool = True) -> str:
        """Gera uma passphrase fácil de memorizar"""
        words = [secrets.choice(self.PASSPHRASE_WORDS) for _ in range(num_words)]
        
        if capitalize:
            words = [w.capitalize() for w in words]
        
        passphrase = separator.join(words)
        
        if add_number:
            passphrase += separator + str(secrets.randbelow(9999)).zfill(4)
        
        return passphrase
    
    def generate_pin(self, length: int = 6) -> str:
        """Gera um PIN numérico"""
        return ''.join(secrets.choice(string.digits) for _ in range(length))
    
    def check_password_strength(self, password: str) -> Tuple[int, str, str]:
        """
        Verifica a força de uma senha
        Retorna: (pontuação, nivel, cor)
        """
        score = 0
        feedback = []
        
        # Comprimento
        length = len(password)
        if length >= 16:
            score += 30
        elif length >= 12:
            score += 20
        elif length >= 8:
            score += 10
        else:
            feedback.append("Senha muito curta!")
        
        # Variedade de caracteres
        if any(c in string.ascii_lowercase for c in password):
            score += 10
        else:
            feedback.append("Adicione letras minúsculas")
        
        if any(c in string.ascii_uppercase for c in password):
            score += 10
        else:
            feedback.append("Adicione letras maiúsculas")
        
        if any(c in string.digits for c in password):
            score += 10
        else:
            feedback.append("Adicione números")
        
        if any(c in self.DEFAULT_SYMBOLS for c in password):
            score += 15
        else:
            feedback.append("Adicione símbolos")
        
        # Complexidade adicional
        if length >= 12 and len(set(password)) >= length * 0.7:
            score += 15
        
        # Penalidades
        if password.lower() in ['password', 'senha', '12345678', 'qwerty']:
            score = 0
            feedback.append("Senha muito comum!")
        
        # Determina o nível
        if score >= 80:
            level = "MUITO FORTE"
            color = Fore.GREEN
        elif score >= 60:
            level = "FORTE"
            color = Fore.LIGHTGREEN_EX
        elif score >= 40:
            level = "MÉDIA"
            color = Fore.YELLOW
        elif score >= 20:
            level = "FRACA"
            color = Fore.LIGHTYELLOW_EX
        else:
            level = "MUITO FRACA"
            color = Fore.RED
        
        return score, level, color
    
    def display_password(self, password: str, label: str = "Senha Gerada"):
        """Exibe a senha de forma destacada"""
        score, level, color = self.check_password_strength(password)
        
        print(f"\n{Fore.GREEN}{Style.BRIGHT}✓ {label}:{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'─'*70}")
        print(f"{Back.BLACK}{Fore.WHITE}{Style.BRIGHT}  {password}  {Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'─'*70}")
        print(f"{Fore.WHITE}Comprimento: {Fore.YELLOW}{len(password)} caracteres")
        print(f"{Fore.WHITE}Força: {color}{Style.BRIGHT}{level} ({score}/100){Style.RESET_ALL}")
        self._display_strength_bar(score)
        print()
    
    def _display_strength_bar(self, score: int):
        """Exibe uma barra de força da senha"""
        bar_length = 50
        filled = int((score / 100) * bar_length)
        
        if score >= 80:
            bar_color = Fore.GREEN
        elif score >= 60:
            bar_color = Fore.LIGHTGREEN_EX
        elif score >= 40:
            bar_color = Fore.YELLOW
        else:
            bar_color = Fore.RED
        
        bar = f"{bar_color}{'█' * filled}{Fore.WHITE}{'░' * (bar_length - filled)}"
        print(f"{Fore.WHITE}[{bar}{Fore.WHITE}]")
    
    def quick_generate(self):
        """Gera uma senha rápida com configurações padrão"""
        self.print_header()
        print(f"{Fore.YELLOW}{Style.BRIGHT}🚀 GERAÇÃO RÁPIDA{Style.RESET_ALL}\n")
        password = self.generate_password()
        self.display_password(password)
        input(f"{Fore.CYAN}Pressione ENTER para continuar...{Style.RESET_ALL}")
    
    def custom_generate(self):
        """Gera uma senha personalizada"""
        self.print_header()
        print(f"{Fore.YELLOW}{Style.BRIGHT}⚙️  SENHA PERSONALIZADA{Style.RESET_ALL}\n")
        
        config = PasswordConfig()
        
        try:
            # Comprimento
            length = input(f"{Fore.WHITE}Comprimento da senha (8-128) [{Fore.YELLOW}16{Fore.WHITE}]: ")
            config.length = int(length) if length else 16
            config.length = max(8, min(128, config.length))
            
            # Opções
            config.use_uppercase = self._get_yes_no("Incluir letras MAIÚSCULAS?", True)
            config.use_lowercase = self._get_yes_no("Incluir letras minúsculas?", True)
            config.use_digits = self._get_yes_no("Incluir números?", True)
            config.use_symbols = self._get_yes_no("Incluir símbolos?", True)
            config.exclude_ambiguous = self._get_yes_no("Excluir caracteres ambíguos (0, O, 1, l, I)?", True)
            
            print(f"\n{Fore.CYAN}Gerando senha...{Style.RESET_ALL}")
            password = self.generate_password(config)
            self.display_password(password)
            
        except ValueError as e:
            print(f"{Fore.RED}Erro: {e}{Style.RESET_ALL}")
        
        input(f"{Fore.CYAN}Pressione ENTER para continuar...{Style.RESET_ALL}")
    
    def passphrase_generate(self):
        """Gera uma passphrase"""
        self.print_header()
        print(f"{Fore.YELLOW}{Style.BRIGHT}📝 PASSPHRASE (Fácil de Memorizar){Style.RESET_ALL}\n")
        
        try:
            num_words = input(f"{Fore.WHITE}Número de palavras (3-8) [{Fore.YELLOW}4{Fore.WHITE}]: ")
            num_words = int(num_words) if num_words else 4
            num_words = max(3, min(8, num_words))
            
            separator = input(f"{Fore.WHITE}Separador [{Fore.YELLOW}-{Fore.WHITE}]: ") or "-"
            capitalize = self._get_yes_no("Capitalizar palavras?", True)
            add_number = self._get_yes_no("Adicionar número no final?", True)
            
            print(f"\n{Fore.CYAN}Gerando passphrase...{Style.RESET_ALL}")
            passphrase = self.generate_passphrase(num_words, separator, capitalize, add_number)
            self.display_password(passphrase, "Passphrase Gerada")
            
        except ValueError as e:
            print(f"{Fore.RED}Erro: {e}{Style.RESET_ALL}")
        
        input(f"{Fore.CYAN}Pressione ENTER para continuar...{Style.RESET_ALL}")
    
    def pin_generate(self):
        """Gera um PIN numérico"""
        self.print_header()
        print(f"{Fore.YELLOW}{Style.BRIGHT}🔢 PIN NUMÉRICO{Style.RESET_ALL}\n")
        
        try:
            length = input(f"{Fore.WHITE}Comprimento do PIN (4-12) [{Fore.YELLOW}6{Fore.WHITE}]: ")
            length = int(length) if length else 6
            length = max(4, min(12, length))
            
            print(f"\n{Fore.CYAN}Gerando PIN...{Style.RESET_ALL}")
            pin = self.generate_pin(length)
            self.display_password(pin, "PIN Gerado")
            
        except ValueError as e:
            print(f"{Fore.RED}Erro: {e}{Style.RESET_ALL}")
        
        input(f"{Fore.CYAN}Pressione ENTER para continuar...{Style.RESET_ALL}")
    
    def multiple_generate(self):
        """Gera múltiplas senhas"""
        self.print_header()
        print(f"{Fore.YELLOW}{Style.BRIGHT}🔄 MÚLTIPLAS SENHAS{Style.RESET_ALL}\n")
        
        try:
            count = input(f"{Fore.WHITE}Quantas senhas gerar (1-20) [{Fore.YELLOW}5{Fore.WHITE}]: ")
            count = int(count) if count else 5
            count = max(1, min(20, count))
            
            print(f"\n{Fore.CYAN}Gerando {count} senhas...{Style.RESET_ALL}\n")
            
            for i in range(count):
                password = self.generate_password()
                score, level, color = self.check_password_strength(password)
                print(f"{Fore.WHITE}{i+1:2d}. {Back.BLACK}{Fore.WHITE}{password}{Style.RESET_ALL}  "
                      f"{color}[{level}]{Style.RESET_ALL}")
            
            print()
            
        except ValueError as e:
            print(f"{Fore.RED}Erro: {e}{Style.RESET_ALL}")
        
        input(f"{Fore.CYAN}Pressione ENTER para continuar...{Style.RESET_ALL}")
    
    def check_strength(self):
        """Verifica a força de uma senha fornecida"""
        self.print_header()
        print(f"{Fore.YELLOW}{Style.BRIGHT}🔍 VERIFICAR FORÇA DE SENHA{Style.RESET_ALL}\n")
        
        password = input(f"{Fore.WHITE}Digite a senha para verificar: {Style.RESET_ALL}")
        
        if password:
            score, level, color = self.check_password_strength(password)
            
            print(f"\n{Fore.CYAN}{'─'*70}")
            print(f"{Fore.WHITE}Senha: {Back.BLACK}{Fore.WHITE}{password}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'─'*70}")
            print(f"{Fore.WHITE}Comprimento: {Fore.YELLOW}{len(password)} caracteres")
            print(f"{Fore.WHITE}Força: {color}{Style.BRIGHT}{level} ({score}/100){Style.RESET_ALL}")
            self._display_strength_bar(score)
            
            # Feedback detalhado
            print(f"\n{Fore.YELLOW}Análise Detalhada:{Style.RESET_ALL}")
            has_lower = any(c in string.ascii_lowercase for c in password)
            has_upper = any(c in string.ascii_uppercase for c in password)
            has_digit = any(c in string.digits for c in password)
            has_symbol = any(c in self.DEFAULT_SYMBOLS for c in password)
            
            self._print_check(has_lower, "Contém letras minúsculas")
            self._print_check(has_upper, "Contém letras MAIÚSCULAS")
            self._print_check(has_digit, "Contém números")
            self._print_check(has_symbol, "Contém símbolos")
            self._print_check(len(password) >= 12, "Comprimento adequado (≥12)")
            self._print_check(len(set(password)) >= len(password) * 0.7, "Boa variedade de caracteres")
            print()
        
        input(f"{Fore.CYAN}Pressione ENTER para continuar...{Style.RESET_ALL}")
    
    def _print_check(self, condition: bool, text: str):
        """Imprime um item de verificação"""
        if condition:
            print(f"  {Fore.GREEN}✓{Fore.WHITE} {text}{Style.RESET_ALL}")
        else:
            print(f"  {Fore.RED}✗{Fore.WHITE} {text}{Style.RESET_ALL}")
    
    def settings_menu(self):
        """Menu de configurações"""
        self.print_header()
        print(f"{Fore.YELLOW}{Style.BRIGHT}⚙️  CONFIGURAÇÕES PADRÃO{Style.RESET_ALL}\n")
        
        print(f"{Fore.WHITE}Configurações atuais:")
        print(f"  Comprimento: {Fore.CYAN}{self.config.length}")
        print(f"  {Fore.WHITE}Maiúsculas: {self._bool_color(self.config.use_uppercase)}")
        print(f"  {Fore.WHITE}Minúsculas: {self._bool_color(self.config.use_lowercase)}")
        print(f"  {Fore.WHITE}Números: {self._bool_color(self.config.use_digits)}")
        print(f"  {Fore.WHITE}Símbolos: {self._bool_color(self.config.use_symbols)}")
        print(f"  {Fore.WHITE}Excluir ambíguos: {self._bool_color(self.config.exclude_ambiguous)}")
        
        print(f"\n{Fore.YELLOW}Deseja alterar as configurações? (s/n): {Style.RESET_ALL}", end='')
        if input().lower() == 's':
            self.config.length = int(input(f"{Fore.WHITE}Comprimento (8-128): ") or self.config.length)
            self.config.use_uppercase = self._get_yes_no("Usar maiúsculas?", self.config.use_uppercase)
            self.config.use_lowercase = self._get_yes_no("Usar minúsculas?", self.config.use_lowercase)
            self.config.use_digits = self._get_yes_no("Usar números?", self.config.use_digits)
            self.config.use_symbols = self._get_yes_no("Usar símbolos?", self.config.use_symbols)
            self.config.exclude_ambiguous = self._get_yes_no("Excluir ambíguos?", self.config.exclude_ambiguous)
            print(f"\n{Fore.GREEN}✓ Configurações atualizadas!{Style.RESET_ALL}\n")
        
        input(f"{Fore.CYAN}Pressione ENTER para continuar...{Style.RESET_ALL}")
    
    def _bool_color(self, value: bool) -> str:
        """Retorna uma string colorida para booleano"""
        if value:
            return f"{Fore.GREEN}Sim{Style.RESET_ALL}"
        return f"{Fore.RED}Não{Style.RESET_ALL}"
    
    def _get_yes_no(self, question: str, default: bool = True) -> bool:
        """Faz uma pergunta sim/não"""
        default_text = "S/n" if default else "s/N"
        response = input(f"{Fore.WHITE}{question} ({Fore.YELLOW}{default_text}{Fore.WHITE}): ").lower()
        
        if not response:
            return default
        return response in ['s', 'sim', 'y', 'yes']
    
    def run(self):
        """Executa o programa principal"""
        while True:
            self.print_header()
            self.print_menu()
            
            choice = input(f"{Fore.YELLOW}Escolha uma opção: {Style.RESET_ALL}")
            
            if choice == '1':
                self.quick_generate()
            elif choice == '2':
                self.custom_generate()
            elif choice == '3':
                self.passphrase_generate()
            elif choice == '4':
                self.pin_generate()
            elif choice == '5':
                self.multiple_generate()
            elif choice == '6':
                self.check_strength()
            elif choice == '7':
                self.settings_menu()
            elif choice == '0':
                self.print_header()
                print(f"{Fore.GREEN}{Style.BRIGHT}Obrigado por usar o Gerador de Senhas! 👋{Style.RESET_ALL}\n")
                sys.exit(0)
            else:
                print(f"{Fore.RED}Opção inválida! Tente novamente.{Style.RESET_ALL}")
                input(f"{Fore.CYAN}Pressione ENTER para continuar...{Style.RESET_ALL}")


def main():
    """Função principal"""
    try:
        generator = PasswordGenerator()
        generator.run()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.YELLOW}Programa interrompido pelo usuário.{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}Erro inesperado: {e}{Style.RESET_ALL}")
        sys.exit(1)


if __name__ == "__main__":
    main()
