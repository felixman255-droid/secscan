# Changelog

## 1.1.1 (2026-11-28)

### Documentação

- README reorganizado, com banner de antes e depois, diagrama de fluxo e selos.
- Explicações longas movidas para `docs/`; `SKILL.md` fica só com as instruções do agente.
- Exemplos de relatório e de baseline gerados de um projeto fictício.
- CI passa a rodar também em Python 3.11.

## 1.1.0 (2026-11-28)

- Instalado como plugin, ferramentas, cache e relatórios ficam na pasta de dados do plugin e
  sobrevivem a atualizações.
- Nova flag `--home`, que mostra onde as ferramentas estão.

## 1.0.0 (2026-11-28)

Primeira versão numerada, instalável como plugin do Claude Code pelo marketplace do próprio
repositório.

### Recursos

- Quatro camadas num relatório só: segredos (gitleaks), dependências (osv-scanner), código
  (semgrep) e infraestrutura (trivy).
- Relatório em Markdown e SARIF, baseline `.secscanignore`, `--exclude-rule` e seção **Escopo**.

### Correções feitas antes desta versão

- Exclusões deixavam de ver segredos em `.github/`, em arquivos como `distance.py` e em projetos
  sob uma pasta chamada `build`.
- O baseline podia transferir a aceitação de um achado para outro segredo.

**Quem tem um `.secscanignore` anterior a estas correções precisa gravá-lo de novo**, porque a
identidade dos achados de segredos e de código mudou.
