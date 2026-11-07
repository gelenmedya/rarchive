# rarchive ölçümleri

Makine: Ryzen 7 9800X3D (8 çekirdek / 16 iş parçacığı), NVMe, Windows 11. Arşivler işletim
sisteminin dosya önbelleğinde (sıcak). Çıktı belleğe çözülüp CRC32 alınıyor, diske yazılmıyor
(UnRAR da aynı şekilde ölçüldü). Araçlar: `rarspike` (`cmp`, `one`, `probe`, `burn`).

## Hız (2026-11-06, `cc3cf2b`, yüksek öncelik, 3 denemenin en iyisi)

| Arşiv | UnRAR (C++) | rarchive `extract` | rarchive `extract_parallel` |
|---|---|---|---|
| RustLegacyRemake2022.rar — WinRAR, 1,3 GB, 32 MB sözlük, 195 dosya | 2,79 s | 0,98 s (2,8×) | 0,28 s (**10,0×**) |
| The Forest — WinRAR, 1,2 GB, neredeyse tamamı saklı | 0,70 s | 0,18 s (3,9×) | 0,17 s (4,1×) |
| bench-solid.rar — rars, 400 MB, katı | 0,95 s | 0,21 s (**4,5×**) | 0,21 s (4,6×) |
| bench.rar — rars, 400 MB, normal, 520 dosya | 1,03 s | 0,57 s (1,8×) | 0,063 s (**16,3×**) |

Doğruluk: her dosyanın CRC32'si arşivdekiyle karşılaştırıldı; ayrıca WinRAR ile yapılmış CC0
arşivler (`crates/rarchive/tests/data/winrar`) bayt bayt test ediliyor, iki çözme yolu da.

## İşlemci ve bellek (tek çalıştırma)

UnRAR da çok iş parçacıklı: ortalama ~2 çekirdek kullanıyor. Toplam işlemci zamanı (ne kadar iş
yapıldığı) rarchive'da daha düşük:

| | UnRAR | rarchive paralel |
|---|---|---|
| bench-solid, işlemci-saniye | 2,36 | 0,91–1,06 |
| RustLegacy, işlemci-saniye | 5,08 | 3,6–3,8 |

Tepe bellek (RustLegacy, paralel): bütçe yokken 385–523 MB; 256 MB bütçeyle (varsayılan)
237–252 MB. Ölçüm düzeneğinin kendisi de bellek tutuyor (UnRAR satırında 430 MB'nin çoğu,
dosyaları tümüyle belleğe okuyan test kodundan).

## Takılma (ön plan yoklaması)

`probe`: 8 normal öncelikli iş parçacığı, her biri 2 ms iş + 4 ms uyku (bir oyunun kare
döngüsü yerine). "Gecikme": 2 ms'lik işin ne kadar uzadığı, yani işlemcinin başkasına verildiği
süre. Çıkartma arka arkaya tekrarlanırken 8 sn ölçüldü.

| Yük | gecikmeli kare (>4 ms) | en kötü |
|---|---|---|
| yük yok | %0,02–0,03 | 4–7 ms |
| UnRAR | %0,06–0,15 | 7–17 ms |
| rarchive paralel, normal öncelik | %2,1–2,8 | 67–115 ms |
| rarchive paralel, düşük öncelik (varsayılan) | %0,4–1,1 | 11–47 ms |

Bu tablo **gürültülü**: ölçüm sırasında başka programlar sürekli ~7–8 çekirdek kullanıyordu
(bir IDE, başka bir derleme, Robocopy) ve bir sonraki turda yük yokken bile %3,4 gecikme
görüldü. Sağlam sonuç: normal öncelikte paralel çıkartma ön planı belirgin şekilde takıltıyor,
bu yüzden varsayılan düşük öncelik (`Priority::Low`: en düşük normal sınıf öncelik, uyanma
artışı kapalı). Kesin karşılaştırma makine boşken tekrarlanmalı.

## Denenen ve bırakılanlar

- Huffman tablosu 9/11/12 bit: 10 bitten farkı gürültü içinde.
- BMI2 kopyası (çalışırken seçiliyor): Zen 5'te fark yok; Intel'de değişken kaydırmalar daha
  pahalı olduğu için yararlı olması beklenir, ölçülmedi.
- Uygulayıcıda eşleşme kaynağını önceden getirme: %20–60 yavaşlattı, kaldırıldı.
- 8 baytlık komutlar: hız farkı yok, bellek yarıya indi; kaldı.

## ZIP ve 7z, diske açma (2026-11-06)

Aynı 381 MB / 520 dosyalık veri, NanaZip 7.0 ile normal ayarlarda paketlendi (ZIP: Deflate,
7z: LZMA2 tek klasör, 3 bağımsız LZMA2 parçası). Diske açma, yüksek öncelik, 3 denemenin
en iyisi; işlemci = toplam işlemci süresi.

| | rustyfiles (rarchive) | NanaZip | Windows tar |
|---|---|---|---|
| ZIP | **0,39 s** (işlemci 1,17 s, tepe 49 MB) | 1,71 s | 0,85–0,99 s |
| 7z | 1,34 s (işlemci 3,0 s, tepe 350 MB) | **1,27 s** (2,3 s, 461 MB) | 3,5 s |

7z'de sınır LZMA çözücünün tek çekirdek hızı (`lzma-rust2`, ~155 MB/s parça başına); üç
parça paralel çözülüyor. Önceki 7z yolu (`sevenz-rust2`) 1,47 s ve 621 MB idi. Bellek
bütçesi artık dinamik: boş belleğin 1/8'i (256 MB–2 GB); 256 MB'de bu arşiv 1,8 s sürüyor.

## RAR 1.5–4.x (RAR 4) okuma hızı (2026-11-06)

Aynı yöntem: belleğe çöz + CRC32, 7 denemenin en iyisi, UnRAR ve rarchive sırayla (`rar4work/spike`,
`spike4`; UnRAR yalnızca ölçüt olarak `unrar` kutusuyla çalıştırıldı). Arşivler `rars` yazıcısıyla yapıldı
(WinRAR 3.x/4.x'in yazdığı akışlarla aynı biçim; her üretilen arşiv UnRAR ile doğrulandı). Makine başka
işlerle tam boş değildi: UnRAR'ın kendi süresi koşudan koşuya ±%15 oynuyor, bu yüzden 0,95–1,10× aralığı
"başa baş" demek.

| Arşiv | UnRAR | rarchive `extract` | rarchive `extract_parallel` |
|---|---|---|---|
| bench4-lz — LZ, normal, 517 dosya, 290 MB (filtreli ikili veri) | 1,23 s | 1,08 s (1,14×) | 0,134 s (**9,2×**) |
| bench4-solid — LZ, katı, 290 MB | 1,62 s | 1,04 s (**1,56×**) | 0,86 s (1,9×; katı akış bölünemez) |
| bench4-ppmd — PPMd, normal, 2143 dosya, 42 MB (Rust kaynak metni) | 3,22 s | 3,16 s (1,02×) | 0,62 s (**5,2×**) |
| bench4-ppmd-solid — PPMd, katı, 42 MB | 2,68 s | 2,50 s (1,07×) | 2,38 s (1,13×; katı akış bölünemez) |
| bench4-text-lz — LZ, katı, 42 MB metin | 0,151 s | 0,066 s (**2,3×**) | 0,044 s (3,4×) |
| farmanager170.rar — WinRAR 3.x, katı PPMd, 3,3 MB (gerçek arşiv) | 0,260 s | 0,207 s (1,25×) | — |
| bench4-v20 — RAR 2.0 (unpack 20), 31 MB metin | 0,145 s | 0,060 s (**2,4×**) | 0,023 s (6,2×) |
| bench4-v15 — RAR 1.5 (unpack 15), 31 MB metin | 0,206 s | 0,145 s (1,42×) | 0,045 s (4,6×) |

Nerede kaybediyoruz / kazanmıyoruz: PPMd tek akışta UnRAR ile **başa baş** (1,02× ve 1,07×; ayrı koşularda 0,97×
de görüldü). PPMd modeli ardışık, katı akış ya da tek büyük dosya paralelleşmiyor; kazanç yalnızca normal
(dosya başına bağımsız) arşivlerde çok dosyayı eşzamanlı çözmekten geliyor. RAR 4'te RAR 5'teki gibi blok
paralel ayrıştırma yok (akış bit düzeyinde ardışık, blok sınırı bilinemiyor).

Ölçüm sırasında bulunan darboğazlar: PPMd modelinin 25 MB'lık alanını her dosyadan sonra bırakıp yeniden
ayırmak (normal PPMd arşivinde %25 yavaşlık; artık az kullanılan model tutuluyor, yalnızca ≥4 MB çözülmüş
gruplardan sonra bırakılıyor) ve model belleğine her erişimde sınır denetimi (~%30: erişimler artık
ofseti son 8 bayta sıkıştırıyor, panik yolu yok).

Doğruluk (hız kıyasından ayrı): her üyenin CRC32'si arşivdekiyle karşılaştırıldı; ayrıca UnRAR'ın aynı
baytları ürettiği arşivlerle bayt bayt test (`crates/rarchive/tests/rar4*.rs`): LZ, katı, PPMd (model
belleği taşıp yeniden başlayan 1–2 MB'lık modeller dahil: ayırıcının birleştirme/yeniden başlatma yolları
UnRAR ile uyumlu), E8/E8E9/ITANIUM/DELTA/RGB/AUDIO süzgeçleri, RAR 2.0 (ses kipi dahil), RAR 1.5,
AES-128 (şifreli üstbilgiler, ≥28 karakterli parola, çok parçalı şifreli setler), eski ve yeni numaralı
çok parçalı setler. Bozuk girdi: 13 200 rastgele bozulmuş arşivde (bayt çevirme, kesme, rastgele bloklar)
sıfır panik, sıfır takılma (> 5 sn).

## ZIP: çok küçük üyeli arşivlerde okuma tamponu (2026-11-06 sabah)

20 000 küçük dosyalık ZIP (82 MB, Windows tar ile yapıldı). `BufReader` her `seek`'te tamponunu
atıyordu; üye başına (yerel başlığa git, başlığı atla, veriyi oku) 1 MB'lık tampon iki kez
dolduruluyordu (~40 GB bellek kopyası). Hedef tampondaysa onu koruyan `SeekBuf` ile:

| | önce | sonra |
|---|---|---|
| `rarchive t` (belleğe çöz + CRC) | 4,9 s (işlemci 1,8 s) | 0,04–0,13 s |
| diske açma (rustyfiles) | ~23 s | 16,6–18,4 s (Windows tar 21,6 s) |

Diske açmada kalan süre dosya oluşturma/kapatma (antivirüs taraması).

RAR5 ile aynı ölçüm (20 000 küçük dosya, `rars` ile katı olmayan arşiv): `rarchive t` 0,05 s; diske açma
17,1–17,6 s (işlemci 19–22 s: dosya oluşturma/kapatmada çalışan dosya sistemi ve antivirüs süzgeç
sürücüsü sürecin hesabına yazılıyor). Okuma tamponunu 1 MB'tan 64 KB'a indirmek fark etmedi
(paralel işçilerde fazladan okuma önemsiz), geri alındı.
