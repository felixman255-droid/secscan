# Instalação em detalhe

[← README](../README.md)

## Instalação

**Windows:**

```powershell
powershell -ExecutionPolicy Bypass -File install.ps1
```

**Linux / macOS:**

```bash
bash install.sh
```

Cria `bin/` (gitleaks + osv-scanner + trivy portáteis) e `.venv/` (semgrep isolado). Nada é
instalado no sistema — só arquivos nesta pasta.

Os três binários são conferidos contra o **SHA-256 oficial** da release fixada antes de serem
usados. Se o hash não bater, o instalador aborta e descarta o arquivo — não existe caminho que
aceite um binário não verificado. Os hashes estão embutidos nos scripts, um por arquitetura
(`x64`/`amd64` e `arm64`).

Ao final, os 9 rulesets do semgrep são pré-baixados para o cache local, para que a primeira
execução já funcione offline.

O trivy funciona de forma diferente, e de propósito. Ele recebe `--cache-dir` apontando para
`cache/trivy` — que fica **vazio**, porque o instalador não pré-aquece nada — junto com
`--skip-check-update`. Nesse estado o `trivy config` usa o bundle de checks **embutido no
binário 0.76.2**, sem tocar na rede. Isso dá três garantias de uma vez:

- **offline de verdade** — nenhuma tentativa de download durante a varredura;
- **determinismo** — os checks ficam atrelados à versão fixada do binário, iguais em Windows,
  Linux e macOS, e imunes a um cache quente de outra versão do trivy no sistema;
- **isolamento** — nada é escrito em `~/.cache/trivy` nem em `%LOCALAPPDATA%\trivy`.

Pré-aquecer o bundle OCI seria pior: o download quebra no Windows quando o caminho temporário
tem espaço, então Linux/macOS usariam o bundle OCI e o Windows cairia no embutido — máquinas
diferentes passariam a reportar achados diferentes.

## Compatibilidade com agentes

O núcleo (`secscan.py`) é um CLI comum — roda sozinho, sem agente nenhum, e é o que faz o
trabalho de verdade.

Para usar **como instrução de agente**, o repositório traz os dois formatos que existem hoje:

| Arquivo | Formato | Agentes |
|---|---|---|
| `SKILL.md` | skill com frontmatter (`name` + `description`) | Claude Code, WorkBuddy, e qualquer agente que leia `SKILL.md` |
| `AGENTS.md` | instruções em Markdown puro | Codex, Cursor, Jules, Amp, Zed e demais leitores de `AGENTS.md` |

O `SKILL.md` serve para Claude Code e WorkBuddy **sem alteração** — o formato é o mesmo. Campos
extras no frontmatter são ignorados por quem não os conhece, então nada quebra.

Instalar como plugin (Claude Code 2.1.275 ou mais novo):

```text
/plugin install secscan --marketplace felixman255-droid/secscan
```

Depois de instalar o plugin, rodar uma vez o instalador descrito em **Instalação** dentro da pasta
do plugin. Atualizações não exigem reinstalar, salvo quando as versões fixas das ferramentas mudam
(o parsing depende delas).

Instalado como plugin, `bin/`, `.venv/`, `cache/` e os relatórios ficam na pasta de dados do plugin
(`plugins/data/secscan-secscan/`), que sobrevive a atualizações e é removida ao desinstalar.
`secscan.py --home` mostra qual é a pasta em uso.

Instalar como skill (Claude Code):

```bash
git clone https://github.com/felixman255-droid/secscan.git ~/.claude/skills/secscan
```

Por projeto, em vez de global: clonar em `.claude/skills/secscan` na raiz do repositório.
Depois rodar o instalador uma vez dentro da pasta clonada.
