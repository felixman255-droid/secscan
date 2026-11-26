# AGENTS.md

Instruções para agentes de código que seguem a convenção `AGENTS.md`
(Codex, Cursor, Jules, Amp, Zed, Gemini CLI e afins).

## O que é este repositório

`secscan` é um CLI de auditoria de segurança que roda três ferramentas gratuitas sobre um projeto
e consolida o resultado num relatório único por severidade:

| Camada | Ferramenta | Pega o quê |
|---|---|---|
| Segredos | gitleaks | token, chave de API, senha commitada |
| Dependências | osv-scanner | CVE em biblioteca de terceiros, com nota CVSS |
| Código (SAST) | semgrep | injeção SQL, `eval`, `shell=True`, cripto fraca, XSS |

O núcleo é `secscan.py`. Ele não depende de nenhum agente — é um script Python comum.

## Antes de rodar

Verificar se `bin/` e `.venv/` existem neste diretório. Se não existirem, instalar uma vez:

```bash
bash install.sh                  # Linux / macOS
```

```powershell
powershell -ExecutionPolicy Bypass -File install.ps1   # Windows
```

A instalação baixa os binários para `bin/` e cria `.venv/` com o semgrep. Nada é instalado no
sistema.

## Como rodar

```bash
./secscan.sh <PROJETO> --out ./security-report
```

```powershell
& ".\secscan.cmd" "<PROJETO>" --out ".\security-report"
```

Sempre apontar `--out` para dentro deste diretório, para não sujar a pasta do projeto auditado.
Usar `--history` quando o alvo for repositório git: é o cenário mais perigoso, porque um segredo
removido do código continua válido no provedor.

Código de saída: `0` passou, `1` encontrou achado na severidade definida em `--fail-on`
(padrão `alta`). Isso permite usar o comando como gate de CI.

## Depois de rodar

1. Ler o `relatorio.md` gerado (o caminho aparece no fim da saída).
2. Resumir por severidade, destacando CRÍTICA e ALTA — não colar o relatório inteiro.
3. Para cada achado relevante, informar arquivo, linha e correção.
4. Dizer explicitamente quais achados são provavelmente falso positivo, e por quê.

## Regras de interpretação

- **Segredo exposto = revogar, não apenas remover.** Se foi commitado, o valor já vazou.
- **CVSS ≥ 9.0 é CRÍTICA**, 7.0–8.9 é ALTA, 4.0–6.9 é MÉDIA.
- **SAST aponta padrão, não prova exploração.** Antes de tratar como urgente, confirmar que o
  dado realmente chega do usuário até o ponto apontado. `eval()` lendo config local não tem o
  peso de `eval()` numa rota HTTP.
- **Sem lockfile, a camada de dependências é pulada** — e é justamente a que mais rende.

## Armadilhas de API já resolvidas (não regredir)

- gitleaks ≥ 8.19 removeu o subcomando `detect`. Usar `git` ou `dir`, com o alvo como argumento
  posicional — `--source` gera `unknown flag`.
- `osv-scanner` expõe `groups[].max_severity` como nota CVSS numérica (`"8.7"`), não rótulo.
- `semgrep` marca `confidence: LOW` em regras de segredo e SQLi por heurística. Não rebaixar
  severidade por isso — rebaixar esconde chave de API exposta.
- `gitleaks dir` não respeita `.gitignore`; `secscan.py` gera um TOML temporário com allowlist.
- Console do Windows não é UTF-8: o terminal usa rótulos ASCII (`CRITICA`), o `relatorio.md`
  mantém acentuação.

## Uso autorizado

Auditar apenas código próprio ou com autorização escrita. Testar sistema de terceiros sem
permissão é crime no Brasil (Lei 12.737/2012) e na maioria das jurisdições.
