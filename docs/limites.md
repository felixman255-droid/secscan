# Limites e interpretação

[← README](../README.md)

## O que roda

| Camada | Ferramenta | Pega o quê |
|---|---|---|
| Segredos | [gitleaks](https://github.com/gitleaks/gitleaks) 8.30.1 | token, chave de API, senha commitada |
| Dependências | [osv-scanner](https://github.com/google/osv-scanner) 2.7.1 | CVE em biblioteca de terceiros, com nota CVSS |
| Código (SAST) | [semgrep](https://semgrep.dev) 1.187 | injeção SQL, `eval`, `shell=True`, cripto fraca, XSS |
| Infraestrutura | [trivy](https://trivy.dev) 0.76.2 | Dockerfile e k8s inseguros: container como root, `privileged`, segredo em `ENV` |

Todas gratuitas. Depois da primeira execução, rodam offline.

A camada de infraestrutura só roda quando existe `Dockerfile`, `*.tf` ou manifesto k8s no
projeto — sem isso ela aparece como "pulado", sem custo de tempo. Para forçar mesmo assim, use
`--iac`.

**`docker-compose.yml` não é escaneado.** O Trivy 0.76 não tem scanner de compose (`Detected
config files num=0`), então o arquivo não ativa a camada. Se o projeto só tiver compose, o
relatório diz isso explicitamente em vez de reportar "limpo" — fingir cobertura seria pior que
admitir a lacuna.

O Trivy entra **só com o scanner `misconfig`**. Os scanners `vuln` e `secret` dele duplicariam
o osv-scanner e o gitleaks: mais ruído, zero cobertura nova.

As versões são fixas de propósito: o `secscan.py` depende do formato JSON de cada ferramenta.
Trocar de versão exige revalidar o parsing com os testes.

## Limites

- **Pastas de dependência e build não são lidas** por gitleaks, osv-scanner e trivy:
  `node_modules`, `dist`, `build`, `.next`, `.next-*` (builds paralelos do Next, como
  `.next-audit`) e as demais de `SKIP_DIRS`. O semgrep usa uma lista menor. A seção
  **Escopo** do `relatorio.md` mostra o que cada camada deixou de fora.
- Nenhuma camada lê `.next` e `.next-*`. Por isso **não há checagem automática de variável de
  servidor embutida por engano no bundle do navegador** (Next.js): conferir à mão em
  `.next/static` e `.next/server` quando isso importar.
- **SAST não prova exploração.** Aponta padrão de risco. Falso positivo é normal — calibre as
  regras com o tempo.
- **A camada de dependências precisa de lockfile ou `requirements.txt`.** O osv-scanner lê
  `requirements.txt`, `poetry.lock`, `uv.lock`, `Pipfile.lock`, `package-lock.json`,
  `go.mod`, `Cargo.lock`, `pom.xml`, `Gemfile.lock` e `composer.lock`. Manifestos puros
  (`pyproject.toml`, `package.json` sem lockfile ao lado) **são ignorados** — nesse caso a
  camada aparece como "pulado", e é justamente a que mais rende na prática. Projeto Python
  com só `requirements.txt` está coberto; projeto com só `pyproject.toml` não está.
- **Não substitui pentest.** Isso pega o que já é conhecido e automatizável. Falha de lógica de
  negócio (usuário A acessando pedido do usuário B) só um humano com contexto encontra.
- **Misconfig de infraestrutura não é vulnerabilidade de código.** O Trivy aponta configuração
  insegura (container como root, `privileged: true`, `latest` sem pin). Um `privileged: true`
  num cluster de teste local não tem o peso do mesmo campo em produção — o relatório não sabe
  distinguir os dois ambientes.
- **A camada de infraestrutura cobre só o que existe em arquivo.** Dockerfile, `.tf` e
  manifesto k8s versionado. Infra provisionada por console, ou imagem construída fora do
  repositório, fica invisível.
- **`docker-compose.yml` fica de fora.** O Trivy 0.76 não escaneia compose. Um
  `privileged: true` num compose só aparece se o arquivo for convertido para k8s ou revisado
  à mão — o `secscan` avisa quando encontra um.
- **A detecção de IaC desce até 3 níveis.** Chart Helm em `deploy/charts/app/Chart.yaml` é
  encontrado; em `a/b/c/d/Chart.yaml` (4 níveis) não é, e a camada fica "pulado". O
  `Chart.yaml` é detectado explicitamente porque fica um nível acima de `templates/`, que
  costuma cair fora do limite — o Trivy não tem esse limite e escaneia o chart inteiro quando
  a camada é ativada.
- **O trivy pode deixar de ver IaC dentro de pastas de dependência.** `node_modules/`,
  `vendor/` e `.terraform/` costumam trazer Dockerfiles de exemplo; o `secscan` os exclui de
  propósito para não reportar infra de terceiros. Se você mantém IaC versionado dentro de uma
  dessas pastas, ele não será escaneado.

## Códigos de saída

| Código | Significado |
|---|---|
| `0` | limpo |
| `1` | achado na severidade definida em `--fail-on` (padrão `alta`) |
| `2` | **alguma ferramenta falhou — varredura incompleta** |

O código `2` existe porque um scanner de segurança que falha em silêncio é pior que um que
quebra. Se o formato do JSON de uma ferramenta mudar, o secscan marca a camada como `FALHOU`
em vez de reportar "nada encontrado".

Se o semgrep abortar sem gravar o JSON (timeout, falta de memória), a camada traz
`semgrep sem relatorio (rc=..., Ns)` e o fim da saída; `rc=124` é o limite de 30 minutos.

## Como interpretar

**CRÍTICA** — corrija hoje. Segredo exposto ou CVE com CVSS ≥ 9.0.
Segredo é sempre crítico porque não basta remover do código: se foi commitado, considere vazado
e **revogue** a credencial.

**ALTA** — corrija nesta sprint. CVSS 7.0–8.9, ou padrão de código explorável.

**MÉDIA** — corrija no ciclo. CVSS 4.0–6.9, ou padrão suspeito que depende de contexto.

O relatório aponta *onde*, não *se é explorável no seu caso*. Um `eval()` num script que só lê
config local não é o mesmo que um `eval()` numa rota HTTP. Confirme o caminho do dado antes de
tratar como urgente.

## Segurança dos dados

Os segredos são **redigidos** no JSON por padrão (`"Secret": "REDACTED"`). Para obter o valor
real — necessário quando a credencial precisa ser revogada — use `--reveal-secrets`, que desliga
a redação.

Com `--reveal-secrets` ativo, o diretório do relatório recebe um marcador `SENSIVEL.txt` e o
console avisa. A rotação de `--keep` trata esses diretórios de forma especial: **apenas o mais
recente é preservado**, os anteriores são apagados mesmo dentro da janela de retenção, porque
acumular dumps de credencial em texto claro só aumenta a exposição sem ganho. Nesse estado o
relatório contém credenciais em texto claro:

- não commite, não anexe em ticket, não envie a serviço externo;
- se um agente de IA estiver operando, ele **não deve abrir** `gitleaks.json` — o valor iria
  para a janela de contexto e para o provedor do modelo. Nesse caso, o agente deve apenas
  informar o caminho do arquivo para você abrir localmente;
- apague o diretório depois de revogar as credenciais.

`security-report/` está no `.gitignore` — não commite.
