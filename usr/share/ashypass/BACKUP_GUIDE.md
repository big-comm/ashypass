# Guia de Configuração de Backup - Ashy Pass

O Ashy Pass agora suporta backup automático para o Google Drive e importação/exportação de CSV.

## Importar/Exportar CSV

Esta funcionalidade permite migrar senhas do Google Chrome para o Ashy Pass e vice-versa.
- **Importar:** Vá em Menu > Importar do Google CSV.
- **Exportar:** Vá em Menu > Exportar para CSV. O arquivo gerado pode ser importado no Google Chrome em `chrome://password-manager/settings`.

## Configuração do Backup no Google Drive

Para ativar o backup automático do seu banco de dados (`ashypass.db`) para o Google Drive, siga os passos abaixo:

### 1. Instalar Dependências
Você precisa instalar as bibliotecas do Google para Python:

```bash
pip install --upgrade google-api-python-client google-auth-httplib2 google-auth-oauthlib
```

### 2. Obter Credenciais do Google
Como este é um aplicativo local, você precisa criar suas próprias credenciais de API (ou usar as fornecidas pelo desenvolvedor, se houver).

1. Acesse o [Google Cloud Console](https://console.cloud.google.com/).
2. Crie um novo projeto.
3. Vá em **APIs e Serviços > Biblioteca** e ative a **Google Drive API**.
4. Vá em **APIs e Serviços > Tela de permissão OAuth**:
   - Selecione "Externo" (ou "Teste" se for só para você).
   - Preencha os dados obrigatórios.
   - Adicione seu email como usuário de teste.
5. Vá em **APIs e Serviços > Credenciais**:
   - Clique em "Criar Credenciais" > **ID do cliente OAuth**.
   - Tipo de aplicativo: **App para computador** (Desktop App).
   - Dê um nome e crie.
6. Baixe o arquivo JSON das credenciais.
7. Renomeie o arquivo para `credentials.json`.

### 3. Configurar o Arquivo
Mova o arquivo `credentials.json` para a pasta de dados do Ashy Pass:

- **Linux:** `~/.local/share/ashypass/credentials.json`

### 4. Uso
Na primeira vez que você clicar em "Sincronizar com Google Drive" no menu do aplicativo, uma janela do navegador se abrirá pedindo permissão para o Ashy Pass acessar seu Drive.
Após autorizar, o backup será criado na pasta "Ashy Pass Backups" no seu Google Drive.
