# Rulesets do semgrep

[← README](../README.md)

## Rulesets por stack

Quando não se passa `--semgrep-config`, o secscan detecta a stack pelos manifestos e soma os
rulesets correspondentes ao `p/default`:

`package.json`/`package-lock.json` → `p/nodejs` · `requirements.txt`/`poetry.lock` → `p/python` ·
`go.mod` → `p/golang` · `pom.xml` → `p/java` · `Gemfile` → `p/ruby` · `composer.json` → `p/php` ·
`Cargo.toml` → `p/rust` · `*.csproj` → `p/csharp`

A busca desce até 3 níveis, então monorepos (`services/api/go.mod`, `apps/web/package.json`)
são detectados — não só a raiz. Diretórios de build e dependência são ignorados, e a varredura
para assim que todas as stacks conhecidas foram encontradas.

Achados duplicados entre rulesets sobrepostos são removidos automaticamente.

## Trocar o ruleset: medir, não assumir

É tentador trocar `p/default` por um pacote "só de vulnerabilidade" (`p/security-audit`,
`p/owasp-top-ten`) para reduzir ruído. **Menos achados não significa menos falso positivo —
pode significar menos cobertura.** Medição num projeto Python de teste com 5 problemas
plantados (chave AWS, PAT do GitHub, SQL injection, `eval`, MD5):

| Configuração | Achados | O que deixou passar |
|---|---|---|
| `p/default` + `p/python` | 5 | — |
| `p/security-audit` + `p/python` | 3 | **chave AWS** e **SQL injection** |
| `p/owasp-top-ten` + `p/python` | 2 | os acima + `eval` |

Os dois pacotes mais estreitos descartaram justamente as duas categorias de maior peso:
credencial exposta e injeção. Antes de trocar, compare **regra por regra** entre as
configurações, não a contagem total.

O caminho mais seguro para ruído continua sendo o baseline: mantenha `p/default` (cobertura) e
use `.secscanignore` para exceção deliberada. Baseline esconde o que você já julgou; ruleset
estreito esconde o que você nunca viu.

Os rulesets fora do `p/default` e das stacks não vêm pré-cacheados pelo instalador — a primeira
execução com eles precisa de rede.

## Regras próprias para docker-compose

Como o Trivy não escaneia compose, `examples/compose-rules.yml` traz regras de Semgrep para o
que mais importa nesses arquivos: `privileged: true`, socket do Docker montado,
`network_mode: host` e `user: root`.

```bash
./secscan.sh ../meu-projeto \
  --semgrep-config p/default,examples/compose-rules.yml
```

Entra na camada SAST que já existe, herdando fingerprint de baseline, mapeamento de severidade e
saída SARIF — sem código novo. É opt-in de propósito: são regras estruturais de YAML, não um
parser de compose, e por isso **não** resolvem `extends`, âncoras/merge (`<<: *defaults`) nem
valores alternativos como `privileged: "true"` entre aspas.

Passar um `--semgrep-config` que não existe no disco marca a camada como `FALHOU` (código de
saída `2`) em vez de reportar zero achados: "limpo" e "não rodou" são coisas diferentes.

O mesmo vale para config que existe mas é inválida — YAML malformado, regra sem `id`. Nesse caso
o semgrep **escreve o JSON normalmente** (com `results` vazio) e sai com `rc=7`; checar só a
existência do relatório transformaria um erro de configuração em "projeto limpo". O secscan
checa o código de saída (`0` e `1` são sucesso; `1` significa achados) e, como segunda rede, se
o JSON veio sem nenhum arquivo analisado **e** com erros registrados.
