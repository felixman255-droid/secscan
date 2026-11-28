# Baseline e supressão de ruído

[← README](../README.md)

## Baseline: o que faz a ferramenta sobreviver ao uso contínuo

Sem baseline, a segunda execução reporta os mesmos 38 achados da primeira e você não consegue
ver **o que é novo**. Na prática, o relatório vira ruído e ninguém mais lê.

**Antes de aceitar, meça a concentração.** Se uma regra genérica responde por metade dos achados,
o problema é a regra, não os 25 achados — e 25 linhas no baseline escondem isso:

```bash
jq -r '.results[].check_id' security-report/*/semgrep.json | sort | uniq -c | sort -rn | head
```

Contagem alta de um mesmo id pede `--exclude-rule` (ou `.semgrepignore`, se o ruído está num
diretório). Baseline é para **exceção de contexto** — o `subprocess` com argumento fixo, o
template já sanitizado —, não para repetição. Em config local o `check_id` sai com o prefixo do
diretório; o id que vale desativar é o sufixo, o mesmo que o relatório mostra.

O baseline registra os achados que você decidiu aceitar. Aceitar tudo de uma vez:

```bash
./secscan.sh ../meu-projeto --write-baseline
```

Isso grava `<alvo>/.secscanignore` — commite esse arquivo junto com o projeto. A partir daí,
só achados novos aparecem, e o código de saída reflete apenas eles.

Para voltar a reportar um achado, apague a linha correspondente no `.secscanignore`.

O fingerprint é calculado sobre `ferramenta + regra + caminho + trecho de código que casou a
regra`, **sem o número da linha**. Mover código, corrigir outra ocorrência ou reordenar achados
não faz um item já aceito reaparecer. No gitleaks o trecho é o `Match` redigido (`VARIAVEL=REDACTED`), e no semgrep sem login é
lido do arquivo. Sem nada que identifique (um token solto na linha), cai no índice de ocorrência:
**não aceitar esses no baseline**, porque a aceitação passa para outro segredo da mesma regra.
Aceitar um `VARIAVEL=...` vale para qualquer valor que essa variável venha a ter.

Regra local (`--semgrep-config examples/compose-rules.yml`) tem um detalhe que quebrava o
baseline: o semgrep monta o id como `<diretório-da-config>.<id-da-regra>`, com o caminho
sanitizado dentro. Como o id entra no fingerprint, um `.secscanignore` gravado em uma máquina
não casava em outra — todo achado virava "novo". O secscan remove esse prefixo e guarda só o id
da regra (`test-eval`, não `F.TemporariosdoGabriel.projeto.test-eval`), o que também deixa a
coluna **Regra** do relatório legível.

A sanitização não é "trocar separador por ponto": o semgrep relativiza ao diretório de trabalho
quando o arquivo está abaixo dele, remove os separadores iniciais (`lstrip("./")`) e **apaga**
os caracteres fora de `[A-Za-z0-9._-]`. Por isso `/tmp/x/regras.yml` vira `tmp.x.` no Linux e
`C:\x\regras.yml` vira `C.x.` no Windows. Chutar a regra acerta uma plataforma e erra a outra —
e o erro é silencioso, porque o strip que não casa simplesmente mantém o id completo.

## Silenciar ruído: quatro níveis, do mais local ao mais amplo

Todos deixam rastro versionado no repositório — nenhum é um ponto cego invisível.

**1. Linha específica — `# nosemgrep`.** Suprime uma regra naquele ponto e a justificativa fica
no `git blame`. É o mecanismo mais preciso:

```python
return hashlib.md5(senha.encode()).hexdigest()  # nosemgrep: python.lang.security.insecure-hash-algorithms-md5.insecure-hash-algorithm-md5
```

Sem o id da regra, `# nosemgrep` suprime **todas** as regras naquela linha — funciona, mas perde
a especificidade e esconde regressão futura.

**2. Caminho inteiro — `.semgrepignore`.** Exclui diretórios de baixa criticidade sem tocar no
comando nem no cache. Funciona mesmo com o `--no-git-ignore` que o `secscan` passa (verificado):

```
legacy/
fixtures/
```

**3. Regra inteira — `--exclude-rule`.** Para a regra que é barulhenta no projeto todo, não em um
ponto. Não existe equivalente em arquivo de configuração quando o ruleset vem do registry
(`p/default`), então a saída é desligar pelo id:

```bash
./secscan.sh ../meu-projeto --exclude-rule python.lang.security.audit.subprocess-shell-true.subprocess-shell-true
```

O id é o mesmo que aparece na coluna **Regra** do relatório. A exclusão age no **resultado**, não
na varredura: o `semgrep.json` bruto continua com os achados (a evidência não some) e o relatório
declara quantos cada regra desligada suprimiu — `test-eval — 2 achado(s) suprimido(s)`. Se você
esperava achados e o número vier zero, o id está errado: id que não casa nada passa em silêncio
no semgrep, então esse zero é o único aviso que existe.

Repassar `--exclude-rule` ao semgrep foi a primeira tentativa e está errado por três motivos: o
`skipped_rules` do JSON vem sempre vazio (não há como contar o que foi suprimido), a flag casa
com o `check_id` cru (que em config local carrega o prefixo do diretório) e um id inválido é
aceito sem erro — o relatório anunciaria uma exclusão que nunca aconteceu.

**4. Achado aceito — `.secscanignore`.** O baseline. Diferente dos três anteriores: age no
resultado, não na varredura, então o achado continua sendo detectado e apenas não conta como
novo. É o único dos quatro que aparece no relatório, na seção **Aceitos por baseline** — com
ferramenta, local e regra, para você conferir a aceitação sem abrir o arquivo do baseline.

Um detalhe que pega as pessoas: **`tests/` e `test/` já são excluídos pelo Semgrep por padrão.**
Não é preciso `.semgrepignore` para eles — e vale saber que código dentro dessas pastas **nunca**
é analisado, mesmo que não seja teste de verdade. `fixture/`, `spec/` e `src/` são varridos
normalmente.

### Os três baldes da triagem

Achado de SAST só orienta ação quando separado em três — e o relatório já entrega a separação
pronta:

| Balde | Como reconhecer | Mecanismo |
|---|---|---|
| **Ruído de regra** | o padrão não se aplica à arquitetura (regra de XSS num template que não renderiza HTML de usuário) | `--exclude-rule` — seção **Regras desativadas**, com a contagem que ela cobria |
| **Verdadeiro em contexto seguro** | o sink existe, mas a entrada é estática ou passa por whitelist | `# nosemgrep` no ponto ou `.secscanignore` — seção **Aceitos por baseline** |
| **Vulnerável acionável** | dado externo chega ao sink sem sanitização | corrigir o código — tabela **Achados** |

Uma taxa única de "falso positivo" mistura os três e não diz onde agir: ruído de regra pede
`--exclude-rule`, contexto seguro pede aceitação pontual, e só o terceiro balde pede código. Os
números de cada seção são o que separa os casos.

## Primeira execução em um projeto real

Ordem que evita os dois erros caros: congelar vulnerabilidade real no baseline, e ligar o CI
antes de saber qual é o ruído de base.

**1. Varredura completa, priorizando o que é urgente.**

```bash
./secscan.sh ../meu-projeto --history
```

Olhar primeiro os segredos (CRÍTICA, revogar em vez de só remover) e as CVEs com coluna
**Corrigir para** preenchida — essas têm correção determinística. SAST por último: é a camada
com mais falso positivo e a que menos muda a decisão de curto prazo.

**2. Triagem antes de gravar o baseline.**

Corrigir o que é real primeiro. `--write-baseline` serve para exceção deliberada — dependência
só de desenvolvimento, padrão interno isolado —, não para zerar o relatório. Baseline gravado
cedo demais congela vulnerabilidade de verdade e o time passa a ignorar a saída.

**3. CI só depois do baseline limpo.**

Com `.secscanignore` commitado, o workflow barra apenas regressão nova (`--fail-on alta`). Ligar
antes disso produz um pipeline vermelho permanente, que é a forma mais rápida de ensinar o time
a ignorar alerta.

Duas coisas que a verificação ponta a ponta confirmou e que valem saber:

- O baseline é **estável**: duas execuções seguidas geram `.secscanignore` idêntico, e um
  segredo novo (mesmo não commitado) derruba a execução com `rc=1`. Sem essa estabilidade, todo
  commit acusaria falha falsa.
- Teste com valor sintético **não prova nada**. `AKIAIOSFODNN7EXAMPLE` está allowlistado pelo
  gitleaks por ser o exemplo canônico da AWS, e uma chave inventada pode não casar com regra
  nenhuma. Um "limpo" obtido assim é falso negativo do teste, não do código.
