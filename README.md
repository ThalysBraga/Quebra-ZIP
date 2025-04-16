# Quebra Zip - README

O **Quebra Zip** é uma ferramenta desenvolvida em Python para tentar descriptografar arquivos ZIP protegidos por senha. Ele suporta diferentes métodos de criptografia (ZipCrypto e AES) e utiliza uma wordlist para realizar ataques de força bruta. A interface gráfica foi construída com a biblioteca `tkinter` e estilizada com `ttkbootstrap` para uma experiência mais moderna.

---

## Funcionalidades Principais

1. **Detecção Automática de Criptografia**:
   - Detecta se o arquivo ZIP está criptografado.
   - Identifica o tipo de criptografia utilizado: **ZipCrypto**, **AES** ou nenhum.

2. **Suporte a Wordlists**:
   - Usa uma wordlist para testar senhas automaticamente.
   - Limpa a wordlist removendo linhas em branco e caracteres desnecessários antes de iniciar o processo.

3. **Interface Gráfica**:
   - Interface amigável com barras de progresso, logs em tempo real e botões para controlar o processo.
   - Suporte a pausa e cancelamento do ataque.

4. **Multithreading**:
   - Utiliza múltiplas threads para acelerar o teste de senhas.

5. **Compatibilidade**:
   - Testa senhas para arquivos ZIP criptografados com **ZipCrypto** usando a biblioteca padrão `zipfile`.
   - Para arquivos criptografados com **AES**, utiliza o utilitário externo `7-Zip`.

---

## Requisitos

Para executar o **Quebra Zip**, você precisará dos seguintes componentes instalados:

1. **Python 3.x**:
   - Certifique-se de ter o Python instalado no seu sistema. Você pode baixá-lo [aqui](https://www.python.org/downloads/).

2. **Bibliotecas Python**:
   - Instale as dependências necessárias com o comando abaixo:
     ```bash
     pip install tkinter ttkbootstrap
     ```

3. **7-Zip**:
   - Para testar senhas de arquivos criptografados com AES, o **7-Zip** deve estar instalado no caminho padrão (`C:\Program Files\7-Zip\7z.exe`). Caso esteja em outro local, ajuste a variável `seven_zip_path` no código.

4. **Wordlist**:
   - Uma lista de palavras (wordlist) no formato `.txt` para testar as possíveis senhas.

---

## Como Usar

1. **Executar o Programa**:
   - Execute o script Python no terminal:
     ```bash
     python quebra_zip.py
     ```

2. **Selecionar Arquivo ZIP**:
   - Clique no botão "Selecionar" ao lado do campo "Arquivo ZIP" e escolha o arquivo ZIP que deseja descriptografar.

3. **Selecionar Wordlist**:
   - Clique no botão "Selecionar" ao lado do campo "Wordlist" e escolha o arquivo `.txt` contendo as possíveis senhas.

4. **Iniciar o Processo**:
   - Clique no botão "Iniciar" para começar o ataque de força bruta.
   - O programa detectará automaticamente o tipo de criptografia e iniciará o teste das senhas.

5. **Monitorar o Progresso**:
   - A barra de progresso mostrará o avanço do processo.
   - O log exibirá as senhas sendo testadas em tempo real.

6. **Pausar ou Cancelar**:
   - Use os botões "Pausar" ou "Cancelar" para interromper o processo quando necessário.

---

### Funções Principais

- **`detect_encryption_and_compression(zip_file_path)`**:
  - Detecta o tipo de criptografia do arquivo ZIP.
  - Retorna `"ZipCrypto"`, `"AES"`, `"Nenhuma"` ou `None` em caso de erro.

- **`test_zipcrypto_password(zip_file_path, password, result_queue)`**:
  - Testa senhas para arquivos criptografados com **ZipCrypto**.

- **`test_aes_password(zip_file_path, password, result_queue)`**:
  - Testa senhas para arquivos criptografados com **AES** usando o utilitário `7-Zip`.

- **`clean_wordlist(wordlist_path)`**:
  - Limpa a wordlist removendo linhas em branco e caracteres desnecessários.

- **`process_passwords(zip_file_path, wordlist_path, encryption_type, progress_var, log_text, stop_event)`**:
  - Processa as senhas da wordlist em paralelo usando threads.

### Classes

- **`ZipCrackerApp(root)`**:
  - Classe principal responsável pela interface gráfica.
  - Gerencia eventos como seleção de arquivos, início, pausa e cancelamento do processo.

---

## Exemplo de Uso

1. Suponha que você tenha um arquivo ZIP chamado `arquivo_protegido.zip` e uma wordlist chamada `senhas.txt`.
2. Abra o programa e selecione o arquivo ZIP e a wordlist.
3. Clique em "Iniciar".
4. Se a senha for encontrada, uma mensagem de sucesso será exibida com a senha descoberta.

---

## Observações

1. **Desempenho**:
   - O desempenho do programa depende do tamanho da wordlist e da complexidade das senhas.
   - Para arquivos grandes ou wordlists extensas, o processo pode levar algum tempo.

2. **Segurança**:
   - Este programa é destinado apenas para fins educacionais e de recuperação de senhas autorizadas.
   - Não utilize esta ferramenta para atividades maliciosas.

3. **Erros Comuns**:
   - Certifique-se de que o caminho do `7-Zip` está correto.
   - Verifique se a wordlist está formatada corretamente (uma senha por linha).

---

## Licença

Este projeto está licenciado sob a **MIT License**. Consulte o arquivo `LICENSE` para mais detalhes.
