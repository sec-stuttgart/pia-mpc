#!/bin/bash
set -e
set -o pipefail

DIR="${1:-paper}"
PAPER_SUBSTITUTION='2!{' # don't replace things on line 2 (where the verbatim command is printed)
PAPER_SUBSTITUTION+='s/OurProtocol/Ours/;s/BaumOrsiniScholl2016/\\cite{BaumOrsiniScholl-TCC-2016}/;s/SpiniFehr2016/\\cite{SpiniFehr-ICITS-2016}/;s/CunninghamFullerYakoubov2016/\\cite{CunninghamFullerYakoubov-ICITS-2017}/;s/KellerPastroRotaru2017/\\cite{KellerPastroRotaru-EUROCRYPT-2018}/;s/BaumCozzoSmart2019/\\cite{BaumCozzoSmart-SAC-2019}/;s/CohenDoernerKondiShelat2023/\\cite{CohenDoernerKondiShelat-CRYPTO-2024}/;s/BaumMelissarisRachuriScholl2023/\\cite{BaumMelissarisRachuriScholl-CRYPTO-2024}/;' # replace protocols with citations
PAPER_SUBSTITUTION+='s/phase/Phase/;s/setup/Setup/;s/offline/Offline/;s/online/Online/;s/verification/Verif./;s/receiver/Com./;s/any_party/P2P/;s/bulletin_board/BC/;' # replace headers / keywords
PAPER_SUBSTITUTION+='s/\\left(//g;'
PAPER_SUBSTITUTION+='s/ \\right)//g;'
PAPER_SUBSTITUTION+='s/ + / \\kern1pt\\relax{+}\\kern1pt\\relax /g;'
PAPER_SUBSTITUTION+='s/\([ \$]\)n\([ \$\^]\)/\1\\PartyCount\2/g;' # replace constants with macros
PAPER_SUBSTITUTION+='s/\([ \${]\)I\([ \$}\^]\)/\1\\InputCount\2/g;'
PAPER_SUBSTITUTION+='s/\([ \${]\)M\([ \$}\^]\)/\1\\MultiplicationCount\2/g;'
PAPER_SUBSTITUTION+='s/\([ \$]\)publicO\([ \$\^]\)/\1\\OutputCount\2/g;'
PAPER_SUBSTITUTION+='}'

mkdir -p $DIR/tables

FINAL_SUBSTITUTION="${SUBSTITUTION-$PAPER_SUBSTITUTION}"
SHORT_FINAL_SUBSTITUTION="${FINAL_SUBSTITUTION};"
SHORT_FINAL_SUBSTITUTION+='s/\^\({[0123456789]\+}\)/\\mathrlap{\^\1}/g;'

python3 scripts/complexity.py table KellerPastroRotaru2017 BaumCozzoSmart2019 BaumOrsiniScholl2016 SpiniFehr2016 CunninghamFullerYakoubov2016 CohenDoernerKondiShelat2023 BaumMelissarisRachuriScholl2023 OurProtocol --input-parties=n --output-parties=n --private-outputs=0 --public-outputs=1 --inputs=1 --additions=0 --scalar-multiplications=0 --input_party=compute_party --output_party=compute_party --communication --O-notation=keep-factors --collapse=3 --midrules | sed "$FINAL_SUBSTITUTION" > $DIR/tables/related-work-communication-core.tex
python3 scripts/complexity.py table KellerPastroRotaru2017 BaumCozzoSmart2019 BaumOrsiniScholl2016 SpiniFehr2016 CunninghamFullerYakoubov2016 CohenDoernerKondiShelat2023 BaumMelissarisRachuriScholl2023 OurProtocol --input-parties=n --output-parties=n --private-outputs=0 --public-outputs=1 --inputs=1 --additions=0 --scalar-multiplications=0 --input_party=compute_party --output_party=compute_party --computation --O-notation=keep-factors --collapse=1 --midrules | sed "$FINAL_SUBSTITUTION" > $DIR/tables/related-work-computation-core.tex

PAPER_SUBSTITUTION='s/c c c c c c c/S\[table-format=3.0\] c S\[table-format=3.0\] c c c c/;s/log-p/{$\\log_2 \\PlaintextModulus$}/;s/log-n/$\\log_2 \\CiphertextSlots$/;s/sec-zk/$\\StatisticalSecurity$/;s/sec-sound/$\\ComputationalSecurity$/;s/log-q/$\\log_2 \\CiphertextModulus$/;s/U \& V/\$\\CiphertextZeroknowledgeBatchSize\$ \& \$\\CiphertextZeroknowledgeAuxilliarySize\$/'

FINAL_SUBSTITUTION="${SUBSTITUTION-$PAPER_SUBSTITUTION}"

python3 scripts/bgv-parameters.py table | sed "$FINAL_SUBSTITUTION" > $DIR/tables/bgv-params-core.tex
