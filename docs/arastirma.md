# rarchive araştırma raporu (saf Rust RAR kütüphanesi + CLI)

Tarih: 2026-11-06. Durum: araştırma aşaması. rarchive kodu YAZILMADI. Bu belge tasarım raporudur.

Okuma kuralları (clean-room): resmi UnRAR C++ kaynağı, `unrar_sys`, `unrar-rs`, `weaver-unrar`, `third_party/unrar` C++ kısımları AÇILMADI. Okunan kaynaklar: RARLAB technote (WebFetch ile), `rars` 0.12.3 (Apache-2.0) kaynağı, `compcol` 0.7.8 ve `rar-codec` 0.1.9 için yalnızca başlık/yapı düzeyinde grep. UnRAR C++ yalnızca zamanlama taban çizgisi olarak çalıştırıldı (harness üzerinden).

Güven işaretleri: **[ölçüm]** bu oturumda ölçüldü, **[kaynak]** okunan bir kaynaktan, **[tahmin]** benim tahminim/çıkarımım, doğrulanmalı.

---

## 0. Yönetici özeti

1. Pratikte önemli olanlar: **RAR5 (v0)** ve **RAR3/4 (RAR 2.9-4.x)**. RAR7 (algoritma sürümü 1) biçim olarak RAR5'in uzantısı; ana fark büyük sözlük (kodlamada). RAR 1.5/2.0 yalnızca eski arşivler için; en sona.
2. Teknote yalnızca **kapsayıcıyı** (başlıklar, vint, şifreleme alanları, hash kayıtları) anlatıyor; **sıkıştırma algoritmasını (Huffman/LZ/filtre bit düzeni) anlatmıyor**. Boşluğu `rars` (Apache-2.0), libarchive `archive_read_support_format_rar5.c` (BSD-2) ve `compcol` (MIT) dolduruyor.
3. Mevcut saf-Rust çözücüler (rars, rar-codec) tek iş parçacığında UnRAR C++'tan ~1.9x yavaş. **Neden yavaş olduğu kodda net**: her sembol için bit konumundan 3 baytlık dilim yeniden okuma, çıktının iki kez kopyalanması (pending -> VecDeque geçmiş -> sink), her push'ta bütçe kontrolü, her sembolde iptal/ilerleme kontrolü. Yani "Rust yavaş" değil, "bu çözücüler hızlı yazılmamış".
4. Profil [ölçüm]: solid arşivde 400 MB çıktı = 60.5 M literal + 24.7 M eşleşme (ortalama 13.8 bayt) ~ **85 M komut**, komut başına ~10.2 bit. rars çözücü fonksiyonu ~1.4-1.6 s harcıyor (~17-19 ns/komut), UnRAR uçtan uca 0.94 s (~11 ns/komut). Eşleşme kopyası ihmal edilebilir (ablasyon: gürültü içinde); tablo kurma %2-3; geriye **sembol çözme gecikme zinciri** ve **çözücü dışı ek yük (%20-30)** kalıyor.
5. UnRAR'ı yenmek gerçekçi: (a) 64-bit bit tamponu + ön-işlenmiş tablo girişleri ile tek iş parçacığında komut başına ~5-7 ns hedefi [tahmin] => solid ~0.5-0.7 s çözme; (b) çıktıyı doğrudan nihai tampona yazıp kopyaları silmek; (c) CRC/BLAKE2sp/filtre/yazma işlerini ayrı iş parçacıklarına almak; (d) **solid arşivde bile** Huffman/komut ayrıştırma aşamasını (veri-bağımsız!) bloklar arası paralelleştirmek (bölüm 4.9, bu raporun en önemli fikri). Non-solid için dosya başına paralellik zaten UnRAR'ı geçiyor (rars paralel 0.60 s vs UnRAR 1.06 s).
6. **Kritik uyarı:** ölçüm arşivleri `rars` kodlayıcısının ürettiği (seviye 1) arşivler. Gerçek WinRAR çıktısının sembol dağılımı, blok boyutu, filtre kullanımı farklı olacak. Gerçek WinRAR arşivleri olmadan "UnRAR'dan hızlı" iddiası kanıtlanmış sayılmaz (bölüm 6.4).
7. Önerilen sonraki adım: **hızlı çekirdek spike'ı** (RAR5 LZ çözücü, yalnızca solid/non-solid fark etmeksizin, `rars`'ın blok ayrıştırıcısı yerine kendi 64-bit bit okuyucusu + tek geçişli çıktı tamponu) ve 3-5 gerçek WinRAR arşivi bulmak. Çıkış kriteri: aynı harness'te solid arşiv çözme <= 0.9 s (UnRAR 0.94 s) tek iş parçacığı çözme-fonksiyonu seviyesinde.

---

## 1. Biçim manzarası

### 1.1 Sürümler ve önem sırası

| Sürüm | Çağ | Algoritma | Bugün önemi |
|---|---|---|---|
| RAR 1.3 / 1.5 | ~1993-1997 | LZ + Huffman (basit) | Çok düşük (eski arşivler) |
| RAR 2.x | 1996-2002 | LZ + Huffman, çok kanallı "audio" modu | Düşük |
| RAR 2.9-4.x ("RAR3") | 2002-2013 | LZ+Huffman **veya PPMd (var.H)**, **RAR VM filtreleri**, AES-128 | **Yüksek**: internetteki eski arşivlerin büyük çoğunluğu, uyarlama/oyun/warez/arşiv sitesi paylaşımları |
| RAR 5.0-6.x | 2013- | LZ+Huffman, yeni filtreler (DELTA/E8/E8E9/ARM), PPMd ve VM YOK | **Yüksek**: yeni varsayılan, WinRAR 5+ çıktısı |
| RAR 7.0 | 2024 | RAR5 + algoritma sürümü 1 (daha büyük sözlük) | Artıyor; WinRAR 7 kullanıcıları büyük sözlük açarsa |

Neden: RAR3 büyük eski arşiv kütüphanesi; RAR5 2013'ten beri varsayılan. Dosya yöneticisi için ikisi de şart; RAR5 önce (daha basit, daha hızlı hedef, tek Huffman çözücü), RAR3'te PPMd ve VM standart filtreleri ek iş.

### 1.2 Özellik matrisi

| Özellik | RAR 1.5 | RAR 2.x | RAR3/4 | RAR5 | RAR7 |
|---|---|---|---|---|---|
| İmza | `Rar!\x1a\x07\x00` (7 bayt) | aynı | aynı | `Rar!\x1a\x07\x01\x00` (8 bayt) [kaynak: technote] | aynı |
| Solid | var | var | var | var (dosya başlığında bit 6) | var |
| Şifreleme | basit XOR benzeri | blok şifre (özel) | AES-128-CBC, KDF SHA-1 x 0x40000 tur (262144) [kaynak: rars crypto/rar30.rs'te var; ayrıntı doğrulanacak] | **AES-256-CBC, PBKDF2-HMAC-SHA256** | aynı |
| Başlık şifreleme (-hp) | yok | yok | var | var (tip 4 başlık) | var |
| Çok parçalı (volume) | var | var | var (.partN.rar / .rNN) | var (ana başlık bit 0/1, başlık bayrakları 0x8/0x10) | var |
| Kurtarma kaydı | yok | yok | var (RR blok 0x78 / servis "RR") | var ("RR" servis başlığı, Reed-Solomon) | var |
| Hızlı açma (quick open) | yok | yok | yok | **var** ("QO" servis; yer belirleyici kayıt) | var |
| Servis başlıkları | - | - | 0x7A "new sub" (CMT, ACL, STM...) | tip 3 (CMT, QO, ACL, STM, RR) | aynı |
| Hash | CRC32 (CRC16 başlık) | CRC32 | CRC32 (başlık CRC16 = CRC32'nin düşük 16 biti) | **CRC32 (başlıkta) + opsiyonel BLAKE2sp (ek kayıt 0x02)** | aynı |
| Filtreler | - | audio (çok kanallı) | RAR VM (standart: E8, E8E9, ITANIUM, RGB, AUDIO, DELTA) | **DELTA, E8, E8E9, ARM** (sabit, VM yok) | aynı |
| Sözlük | 64 KB | 64 KB-1 MB (arşivde 64K-4M kodlanır) | 64 KB - 4 MB | 128 KB x 2^N, **teknote: 4 GB'a kadar (N<=15)** | **64 GB'a kadar kodlanabilir (N<=19; teorik 23 = 1 TB)** [kaynak: technote] |
| Dosya adı | OEM | OEM | OEM + Unicode ek | UTF-8 | UTF-8 |

Notlar:
- RAR5 pratik sözlük sınırları: WinRAR 5/6 tipik 1 GB (64-bit), 256 MB (32-bit); RAR7 4 GB'ye kadar [tahmin, WinRAR sürümlerine göre doğrulanmalı]. Teknote "gerçek uygulamalar daha düşük sınır koyabilir" diyor.
- **RAR7'de değişen** (teknote, "sıkıştırma bilgisi" vint'i): bit 0-5 algoritma sürümü (0 ya da 1; 1 için RAR 7.0+ gerekir), bit 10-14 sözlük gücü (v1'de 15'ten büyük değerler çıkabilir), **bit 15-19 yalnızca v1: ara sözlük boyutları** (`boyut + boyut*değer/32`), **bit 20: v1 kodlaması ama veri v0** (v0 solid akışa v1 dosya eklenirken sözlük büyütmek için). Ayrıca [kaynak: rars `table_length_count(algorithm_version)`] v1'de **mesafe tablosu 64 yerine 80 sembol** (4 GB üzeri mesafeler için) — algoritma sürümü 1 için tablo uzunluğu farklı. Doğrulanacak: v1 için başka değişiklik (ör. uzunluk/mesafe kodlaması) olup olmadığı. rars'ta `algorithm_version` parametresi var, kaynak okunarak bu netleştirilecek (ilk fazda).
- RAR3 şifreleme ayrıntıları ve RAR5 KDF ayrıntıları aşağıda 1.3.

### 1.3 RAR5 şifreleme / KDF

- Teknote: şifreleme sürümü 0 (AES-256), bayrak 0x1 = parola doğrulama verisi (12 bayt), 0x2 = "tweaked checksums" (dosya CRC32/hash'leri anahtarla dönüştürülür), KDF sayısı = log2(PBKDF2 yineleme), tuz 16 bayt, IV 16 bayt. **PRF adı teknotede yok.** Ek kaynak: rars `src/crypto/rar50.rs` ve libarchive: PBKDF2-HMAC-SHA256; varsayılan log2 = 15 (32768 yineleme) [kaynak: rars `crypto/rar50.rs` satır 25-26]. `key` ve `hash_key` iki ayrı 32 baytlık türetim (rars `Key{key, hash_key}`); parola kontrol değeri aynı PBKDF2 akışının ilave 16/32 turundan türetilir [bilgi: 7-Zip/libarchive dokümantasyonundan hatırlanan; rars koduyla doğrulanacak].
- Başlık şifreleme: her başlık 16 bayt IV + AES-CBC (16 baytlık hizalı dolgu).
- Maliyet [tahmin]: 32768 x 2 SHA-256 sıkıştırma ~ SHA-NI ile birkaç ms, SHA-NI yoksa ~20-40 ms. `sha2` crate'i cpufeatures ile otomatik SHA-NI seçer. Sorun değil; **ama** dosya başına farklı tuz olabilir (dosya şifreleme kaydında tuz var; -hp yoksa dosyalar farklı tuzla şifrelenir) -> çok dosyalı şifreli arşivde KDF dosya sayısıyla çarpılır: 10k dosya x 5 ms = 50 s! Çözüm: aynı tuzlu (parola, tuz, log2) üçlüsü için KDF önbelleği; farklı tuzlarda KDF'yi paralel iş parçacıklarında yap. (WinRAR çoğunlukla arşiv genelinde tek tuz kullanır; gerçek arşivle doğrulanmalı.)
- AES-CBC **çözme** paralelleştirilebilir (her blok yalnızca önceki şifreli blokla XOR); AES-NI ile 8 blok boru hattı; `aes` crate'i (AES-NI otomatik) ile 2-6 GB/s [tahmin]. Çözme, çözücü iş parçacığından önce ayrı aşamada yapılabilir.

### 1.4 RAR3/4 şifreleme (özet, yüksek seviye)
AES-128-CBC; anahtar+IV, SHA-1'in parola(UTF-16LE)+8 bayt tuz+3 bayt sayaç üzerinde 0x40000 tur çalıştırılmasından türetilir (IV, belirli turlardan alınan baytlardan). SHA-1 için SHA-NI var; ~262144 sıkıştırma bile dosya başına ~50-100 ms [tahmin] -> aynı önbellek mantığı.

### 1.5 RAR3/4 üst düzey yapı
- Blok başlığı: CRC16 (2) + tip (1) + bayrak (2) + boyut (2) [+ ADD_SIZE (4) bayrak 0x8000]. Tipler: 0x72 işaret, 0x73 ana, 0x74 dosya, 0x75 eski yorum, 0x76 AV, 0x77 eski alt, 0x78 koruma (RR), 0x79 imza, 0x7A yeni alt (servis), 0x7B arşiv sonu.
- Dosya başlığı bayrakları: 0x01 önceki parçadan devam, 0x02 sonrakine devam, 0x04 parola, 0x10 solid, 0xE0 sözlük boyutu (0xE0 = dizin), 0x100 büyük dosya (64-bit), 0x200 Unicode ad, 0x400 tuz, 0x800 sürüm, 0x1000 ek zaman. Paketleme yöntemi 0x30 (store) - 0x35 (en iyi), açma sürümü 15/20/26/29/36 [rars `rar15_40.rs` + genel bilgi; doğrulanacak].
- Çözücü: **ana Huffman (299 sembol), mesafe (60), düşük mesafe (17), uzunluk (28)** + PPMd var.H (blok başında seçim bit'i) + VM filtreleri (standart filtre, CRC+uzunlukla tanınır; keyfi VM programı pratikte nadir).
- PPMd var.H: 7-Zip'in PPMd7 ailesinden farklı aralık kodlayıcı ayrıntıları var; `rars/src/codec/ppmd.rs` (2418 satır) ve `rar-codec/src/ppmd7.rs` (1743 satır) referans olarak okunabilir (Apache-2.0). PPMd çok yavaş bir model: tek iş parçacıklı, bellek-bağımlı (bellek ayırıcı/ağaç gezinme). **PPMd arşivlerinde UnRAR'ı geçmek zor**; hedef "UnRAR'dan yavaş olmamak" (eşit) olmalı, çünkü hız çoğunlukla model güncellemesinin dalları ve önbellek ıskalamalarıdır. Burada fark yaratacak şey bellek yerleşimi (u32 indeksli arena, yapı hizalama) ve dal azaltmadır.

---

## 2. RAR5 çözme hattı

### 2.1 Kapsayıcı (teknote, tam)
Teknoteden tam özet için bkz. kaynak: https://www.rarlab.com/technote.htm. Çekirdek noktalar:
- vint (7 bit veri + devam biti, little-endian, en fazla 10 bayt); diğer tamsayılar LE.
- Genel blok: CRC32 (başlık boyutundan ek alana kadar) + başlık boyutu (vint, **en fazla 3 bayt = 2 MB**) + tip (1 ana, 2 dosya, 3 servis, 4 arşiv şifreleme, 5 son) + bayraklar (0x1 ek alan var, 0x2 veri alanı var, 0x4 bilinmeyeni atla, 0x8 önceki volume'den devam, 0x10 sonrakine devam, 0x20 bağımlı, 0x40 koru) [+ ek alan boyutu] [+ veri boyutu].
- Ana başlık: bayraklar (0x1 volume, 0x2 volume numarası var, 0x4 **solid**, 0x8 kurtarma, 0x10 kilitli); ek kayıt 0x01 **locator** (quick-open ve recovery ofsetleri), 0x02 metadata.
- Dosya/servis başlığı: bayraklar (dizin, unix mtime, CRC32 var, **boyut bilinmiyor**), açılmış boyut, öznitelik, mtime, CRC32, **sıkıştırma bilgisi vint'i** (bkz 1.2), host OS, ad. Ek kayıtlar: 0x01 şifreleme, 0x02 hash (BLAKE2sp, 32 bayt), 0x03 zaman, 0x04 sürüm, 0x05 yönlendirme (symlink/junction/hardlink/copy), 0x06 unix sahip, 0x07 servis verisi.
- Sıkıştırma bilgisi: bit 0-5 algoritma sürümü, bit 6 solid, bit 7-9 yöntem (0 = store, 1-5), bit 10-14 sözlük gücü, 15-19 + 20 yalnızca v1.
- Servis başlıkları: CMT (yorum, sıkıştırılmamış), QO (quick open: CRC'li önbellek yapıları; **güvenlik notu: adı QO'dan gösterip çıkarmada başlıktan okumak aynı sonuç olmalı**), ACL, STM, RR.
- Dosya adı güvenliği: `/` ayırıcı, Windows'ta `\` geçersiz; Unix'te dönüştürülemeyen baytlar U+E080-U+E0FF özel alanına eşlenir.

### 2.2 Sıkıştırılmış veri (teknotede YOK; rars + libarchive + compcol'dan)
Kaynak dosyalar: `rars-0.12.3/src/codec/rar50.rs` (satır 143-380 blok/tablolar, 963-1120 çözme döngüsü, 1969-2045 yuva fonksiyonları), `compcol-0.7.8/src/rar5/decoder.rs`, libarchive `archive_read_support_format_rar5.c` (okunmadı bu oturumda; rars/compcol belgeleri üzerinden dolaylı).

**Blok yapısı** [kaynak: rars `parse_compressed_block`, ayrıntı satır 143-200]: bit akışı **MSB-first** (en anlamlı bit önce). Her sıkıştırılmış blok: 1 bayt bayrak (alt bitler: son baytta kullanılan bit sayısı-1; sonraki alanlar: boyut baytı sayısı-1; "son blok" bit'i; "tablolar var" bit'i), 1 bayt sağlama (XOR sabiti ile), 1-3 bayt blok boyutu, ardından yük. Tablolar yoksa önceki bloktan **devralınır** (solid ve bloklar arası).

**Tablolar** [kaynak: rars `read_table_lengths`]: önce 20 sembollük "seviye" tablosu (her kod uzunluğu 4 bit; değer 15 ardından 4 bit sayaç = sıfır dizisi kaçışı), sonra bu seviye Huffman'ı ile tek akışta şu alfabelerin kod uzunlukları: **ana (306)**, **mesafe (64; v1'de 80)**, **hizalama (16)**, **uzunluk (44)**. Seviye sembolleri 0-15 = doğrudan uzunluk; 16/17 = önceki uzunluğu tekrarla (3+3 bit / 11+7 bit); 18/19 = sıfırları tekrarla (3+3 bit / 11+7 bit) [genel bilgi, rars kodundan doğrulanacak]. En uzun kod 15 bit. Tamamlanmamış ağaçlar kabul edilir (kullanılmayan alfabeler).

**Ana alfabe düzeni** [kaynak: rars çözme döngüsü]: 0-255 literal; 256 filtre; 257 "son uzunluğu aynı rep[0] ile tekrarla"; 258-261 rep[0..3] mesafesiyle eşleşme (uzunluk ayrıca uzunluk tablosundan); 262-305 uzunluk yuvası (44), ardından mesafe yuvası.

**Uzunluk yuvası -> uzunluk**: yuva < 8: `yuva + 2`, ek bit yok. Aksi halde `nbit = (yuva>>2) - 1`, `uzunluk = (((4 | (yuva&3)) << nbit) | ek) + 2`.
**Mesafe yuvası -> mesafe**: yuva < 4: `yuva + 1`; aksi halde `nbit = (yuva-2)>>1`, `mesafe = ((2 | (yuva&1)) << nbit | ek) + 1` (rars `distance_from_slot_parts`). **Uzunluk bonusu**: mesafe > 0x100: +1, > 0x2000: +1, > 0x40000: +1 (yalnızca yeni eşleşmeler). **Hizalama modu**: mesafe nbit >= 4 ve hizalama tablosu "düz değil" ise üst `nbit-4` bit doğrudan + alt 4 bit hizalama Huffman'ından (rars `align_mode`).
**Rep durumu**: 4 girişli LRU `reps[4]` + `last_length`; yeni eşleşme `reps.rotate_right(1)`; rep eşleşmesi `reps[..=i].rotate_right(1)`.
**Filtre kaydı (256)**: [kaynak rars `read_filter`] başlangıç ofseti ve uzunluk (2 bitlik n, ardından (n+1) bayt LE), tip (3 bit: 0 DELTA, 1 E8, 2 E8E9, 3 ARM), DELTA için kanal sayısı (5 bit +1). Aralık, **o ana kadar çözülen çıktıya göre göreli**. UnRAR'ın `MAX_FILTER_BLOCK_SIZE` = 0x400000 (4 MiB) sınırını rars de kullanıyor; kaynak rars yorumu (satır 35-41) — bunu biçim sınırı olarak kabul et, ama filtre sayısı sınırı (8192) bizim savunma sınırımız olmalı.
**Solid durum taşıma**: pencere (son `dict` bayt), `reps`, `last_length`, **son bloğun Huffman tabloları** (sonraki blok "tablo yok" derse kullanılır), filtre listesi dosya sınırında sıfırlanır. x86 filtreleri **dosya-bağıl** adres hesaplar: solid akışta her üyenin başlangıç ofseti bilinmeli (compcol `add_file_boundary` bunu açıkça ele alıyor).
**Dosya sonu**: bloklar dosya sınırını aşmaz mı? rars kodu `block.header.is_last || output.written() >= output_size` ile bitiriyor; yani dosya = bir veya daha çok blok, son blokta "son" bit'i. Gerçek WinRAR arşivinde doğrulanacak (bölüm 4.9 buna bağlı).

### 2.3 Teknotenin atladıkları ve boşluk dolduranlar
| Atlanan | Doldurulan kaynak |
|---|---|
| Blok başlığı, tablolar, sembol düzeni, yuva formülleri, filtre bit düzeni | rars `codec/rar50.rs`; compcol `rar5/`; libarchive rar5.c |
| PRF (PBKDF2-HMAC-SHA256), parola kontrol hesabı, "tweaked checksum" | rars `crypto/rar50.rs`; libarchive |
| RAR3/4 tüm biçim | rars `rar15_40*`, `codec/rar29*`, `rarvm*`; rar-codec; libarchive `archive_read_support_format_rar.c` |
| Kurtarma kaydı (Reed-Solomon) biçimi | rars `recovery/rar5`; (v1 için gerekmez, ama listede) |
| RAR7 v1 farkları | teknote bit düzeni var; algoritma ayrıntısı için rars `algorithm_version` kullanımı |

---

## 3. Profil: zaman nereye gidiyor?

### 3.1 Yöntem ve sınırlar
- Windows'ta profilleyici yok (`samply`, `perf`, `xperf` yok; `wpr` var ama admin gerektirir; UAC tetiklenmedi -> kullanılmadı). Bu yüzden: (a) `rars` 0.12.3'ün **kopyasında** (`rars-prof`, kayıt defterindeki orijinale dokunulmadı) sayaçlar ve zamanlayıcılar eklendi, (b) ablasyon (eşleşme kopyasını sıfır-doldurmayla değiştirme; sembol ayrıştırma veriden bağımsız olduğu için çözme akışı bozulmaz), (c) bağımsız mikro-ölçümler.
- Araçlar: `rarprof` (Cargo projesi; çıktı `target\rarprof`).
- **Ölçüm gürültüsü büyük**: makinede IDE/Spotify vb. çalışıyordu; aynı iş 1.77 s ile 2.3 s arasında oynadı. Aşağıdaki sayılar "en az 3 çalıştırma, mümkünse en iyisi" ama ±%15 oynayabilir. Karar verirken oran/yapı önemli, mutlak değer değil.

### 3.2 Harness yeniden ölçümü (bu oturum, `bench.exe`, en iyi 3) [ölçüm]
| arşiv | UnRAR C++ | rars 1 iş p. | rars paralel | rar-codec |
|---|---|---|---|---|
| normal (520 dosya, 114 MB) | 1.06 s (377 MB/s) | 1.78 s (225) | 0.60 s (671) | 1.77 s (226) |
| solid (109 MB) | 0.94 s (427 MB/s) | 1.77 s (226) | 1.74 s (230) | 1.73 s (232) |

(Görev metnindeki 1.26/1.12 s ilk ölçüm; bu çalıştırmada makine daha sakindi. Oran ~1.7-1.9x aynı.)

### 3.3 Arşiv içeriği istatistiği (rars-prof sayaçları) [ölçüm]
| | solid | normal |
|---|---|---|
| Sıkıştırılmış blok sayısı | 6367 (hepsi tablolu) | 6422 (hepsi tablolu) |
| Paketlenmiş bayt | 108.6 MB | 114.5 MB |
| Literal sayısı | 60.5 M | 64.2 M |
| Yeni eşleşme (sayı / bayt) | 14.8 M / 180 MB (ort. 12.2 B) | 16.3 M / 205 MB (ort. 12.6 B) |
| Rep eşleşmesi (sayı / bayt) | 9.9 M / 160 MB (ort. 16.2 B) | 7.7 M / 131 MB (ort. 17.1 B) |
| Filtre | 0 | 943 filtre, 40.5 MB |
| mesafe <= 8 | 269 K (%1.1 eşleşme) | 361 K |
| mesafe > 1 MiB | 0 | 0 |

Çıkarımlar:
- **Komutların %71'i literal**, ama çıktının %15'i literal. Bit hızı: ~10.2 bit/komut. Ortalama blok: ~17 KB paketli, ~63 KB çıktı (rars kodlayıcısına özgü; WinRAR'da farklı olabilir).
- Solid arşivde filtre YOK (rars solid modda filtre aramıyor olabilir). Gerçek WinRAR exe/dll için E8/E8E9 kullanır, solid dahil.
- Mesafe > 1 MiB hiç yok: rars seviye 1 küçük pencere kullanıyor; WinRAR 32 MB+ (varsayılan RAR5 sözlüğü yüksek, ~32-64 MB [tahmin]) -> **önbellek davranışı** (uzak mesafe = L2/L3 ıskalaması) gerçek arşivlerde daha kötü olacak. Ölçüm arşivi bunu yansıtmıyor.

### 3.4 Zaman dağılımı (rars, solid, tek iş parçacığı) [ölçüm, çalıştırma başına]
| Bileşen | Süre | Pay | Not |
|---|---|---|---|
| Toplam duvar saati (extract_to, null/CRC sink) | 1.8-2.2 s | %100 | çalıştırmalar arası oynama |
| `decode_member...` fonksiyonu toplamı | 1.39-1.64 s | ~%70-75 | sembol çözme + literal push + eşleşme + bellek büyütme |
| - tablo kurma (6367 blok) | 0.04-0.05 s | ~%2-3 | blok başına ~7 µs |
| - blok yükünü okuma (kopya) | 0.007-0.010 s | <%1 | |
| - geçmiş hatırlama (solid) | 0.005-0.006 s | <%1 | |
| - filtre uygulama | 0 (solid) / 0.03 (normal) | <%2 | 40 MB E8 |
| - eşleşme kopyası (ablasyon) | gürültü içinde (<~%10) | küçük | ortalama 13.8 B eşleşme |
| **Çözücü dışı** (üye döngüsü, kaynak okuma, `Box<dyn Write>` kopyası, Vec yaşam döngüsü/sayfa hataları, CRC doğrulama) | ~0.4-0.6 s | **~%20-30** | hipotez: 400 MB için taze Vec = sayfa hatası + sıfırlama + serbest bırakma |
| CRC32 (crc32fast, tüm 400 MB) | ~0.01 s | ~0 | 45-55 GB/s ısınmış önbellekte (çok yüksek görünüyor; yine de ihmal edilebilir) |
| Kaynak dosya okuma (400 MB, ısınmış önbellek) | 0.10-0.28 s | | arşiv için değil, kıyas |
| Disk yazma (400 MB, sync dahil) | ~0.32 s (~1.2 GB/s) | | tek ölçüm, Defender/NTFS etkisi dahil |

Komut başına maliyet: rars çözücü ~17-19 ns/komut (≈75-85 döngü @ ~4.5 GHz) [hesap: 1.5 s / 85.2 M komut]. UnRAR uçtan uca ~11 ns/komut. Bu sayı "Huffman çözme + bit okuma + literal yazma" bölgesinin baskın olduğunu gösteriyor; çünkü hem eşleşme kopyası hem tablo kurma küçük.

### 3.5 rars kodundan tespit edilen yapısal yavaşlıklar [kaynak: rar50.rs]
1. **BitReader**: `bit_pos` (bit cinsinden) tutuluyor; her `peek15` bayt konumu/bit ofsetini yeniden hesaplıyor, `input.get(byte_pos..)` + 3 baytlık `match` dilimi (dal) -> her sembolde 1 bellek yükü + ayrı bayt birleştirme. `read_bits` ayrıca `NeedMoreInput` sınır denetimi + 5 baytlık `match`.
2. **Huffman tablosu**: 10-bitlik hızlı tablo (u32 giriş = 4 KB) + 11-15 bit kodlar için uzunluk uzunluk **döngüsel arama**; semboller `usize` (8 bayt) dizisinde. Hiçbir ön-işlenmiş "temel değer + ek bit sayısı" yok: uzunluk/mesafe için ek tablolar, `length_slot_extra_bits`, `slot_to_length` hesapları sembol sonrası yapılıyor.
3. **Çift kopya**: literal ve eşleşmeler `pending` (64 KB) içine yazılıyor, `flush` ile sink'e veriliyor VE `history` (VecDeque) içine `extend_admitted(iter)` ile (bayt bayt yineleyici!) kopyalanıyor. Streaming yolu bu; "buffer" yolu tüm üyeyi bir Vec'e çözüp sonra filtreliyor (belleği şişiriyor).
4. Her `try_push` bütçe/allowance denetimi; her komutta `poller.check_codec` (iptal/ilerleme) çağrısı.
5. Paralellik yalnızca **dosya başına** (non-solid).
Bu yüzden 225 MB/s; rar-codec de benzer (226 MB/s): `peek32` bayt bayt `acc = (acc<<8)|b` döngüsüyle biriktiriyor; pencere power-of-two ring Vec (iyi), ama bit okuma yavaş. compcol: 9-bit birincil tablo + 16-bit peek, power-of-two ring pencere `vec![0; ws]` (yalnızca varsayılan 1 MiB; büyük sözlükte tahsis maliyeti), `pending` çıktı tamponu; bu oturumda ölçülmedi.

### 3.6 Bellek davranışı
- rars: VecDeque geçmiş (dosya boyutuyla büyür, `dict + dict/4` sınırı), `pending` 64 KB, solid'te geçmiş taşınır; non-streaming yolda tüm üye çıktısı bir Vec (büyük dosyada çıktı boyutu kadar RAM).
- UnRAR (genel bilgi, kaynağa bakılmadı): sözlük boyutunda tahsis. 4 GB sözlük arşivinde 4 GB commit riski; bizim hedefimiz: **çıktı yazıldıkça büyüyen** pencere (bölüm 6).
- Çözücü çalışma kümesi: ana tablo 306 sembol + mesafe 64 + uzunluk 44 + hizalama 16; hızlı tablolar için ~8-16 KB: L1'e (32-48 KB) sığar, pencere + girdi akışı L2/L3 yükünü belirler.

---

## 4. Hız teknikleri (RAR5 odaklı)

Her madde: beklenen etki [tahmin], kaynak/fikir.

### 4.1 64-bit, dalsız yenilemeli bit tamponu
MSB-first akış için sol-hizalı 64-bit tampon: `buf |= be64(ptr) >> nbits; ptr += (63 - nbits) >> 3; nbits |= 56;` (Fabian Giesen, "Reading bits in far too many ways", variant 4; libdeflate `bitbuf`/`REFILL_BITS_BRANCHLESS`). Tüm kod+ek bitler (<= 15 + 24 + 15 + 31 bit...) tek yenilemede sığmayabilir: komut başına en fazla 1-2 yenileme. Girdi sonunda güvenli yavaş yol (8 bayt sıfır dolgu ya da kuyruk için ayrı döngü). Etki: rars'taki bit okuma/sembol maliyetinin ~%40-60'ını kaldırır [tahmin].

### 4.2 Tablo tasarımı
- **Ön-işlenmiş 32-bit giriş** (libdeflate `decode_results`): giriş = {sınıf (literal/rep/uzunluk/filtre/son), kod uzunluğu, ek bit sayısı, taban değer}. Uzunluk ve mesafe için taban + ek bit sayısı tabloya gömülü -> sembol sonrası dal/aritmetik yok.
- Birincil tablo: ana için 11-12 bit (2^11 x 4 B = 8 KB), mesafe 8-9 bit, uzunluk 8 bit; uzun kodlar için alt tablo (libdeflate ana tablo 11 bit, alt tablo; zstd huff0 11-12 bit). Mesafe taban değeri 31 bit ek bitle 32 bite sığmaz -> mesafe girişi u64 ya da (taban, nbit) ayrı iki dizi.
- **Çok sembollü (çift literal) giriş** (zstd huff0 X2, Charles Bloom'un Huffman serisi): iki kısa literal toplam <= birincil bit sayısıysa tek girişte iki literal. Bu veride komutların %71'i literal -> literal koşuları ortalama ~2.4 -> kazanç %15-30 [tahmin]. **Dikkat:** blok başına ~63 KB çıktı olduğundan tablo kurma süresi önemli; çift sembol tablosunu yalnızca blok yeterince büyükse (ör. paketli > 16 KB) kur ya da tembel kur. Ölçüm: şu an tablo kurma %2-3; 4x daha pahalı olursa %8-12 => sınırda.
- Tablo kurma hızı: sayarak sıralı doldurma (canonical, `rars` benzeri scatter) + `memset`-benzeri alan doldurma; 7 µs/blok'tan 2-3 µs'ye indirilebilir [tahmin].

### 4.3 Hızlı literal koşuları
Ana döngü: bir komut çözülürken ardışık literal ise, tek yenilemeyle (64 bit ~ 5-6 literal bit-şartıyla) 2-3 literal ardışık çöz, tek 8 baytlık yazma (üstüne yazmaya izin veren kuyruk payı ile). libdeflate: literal başına tek yazma + önceden "bir sonraki girişi yükle" (entry prefetch) -> yük gecikmesi kaçınılır (`entry = table[bitbuf & mask]` bir sonraki turun yüklemesi mevcut komutun işlemesiyle örtüşür). Bu "yazma-oku bağımlılığı kırma" tek iş parçacığında asıl kazanç.

### 4.4 Eşleşme kopyası
Ölçüm: ort. eşleşme 13.8 B, mesafe<=8 yalnızca %1.1 -> hızlı yol: mesafe >= 16 ise 16 B (SSE2) kopyalar döngüsü, uzunluk kadar; fazlasını yazmaya izin veren **kuyruk payı** (pencere/çıktı sonunda >= 64 B ek). mesafe < 16: desen yayma (8 B kayıtta) ya da tekrarlı çift kat kopya (rars'ın "doubling" tekniği doğru, ama 1 B/2 B/4 B için özel yol: mesafe 1 = bayt doldurma). Etki: toplamda küçük (ablasyon: <%10), ama büyük dosyalarda (ortalama eşleşme uzun) önemli. **Gerçek WinRAR arşivinde** eşleşmeler daha uzun/sıkıştırma oranı yüksek -> kopya payı artar; metin/tekrarlı veride (ör. sıfır dolu VM disk) eşleşme çok uzun: büyük bellek-bağlı kopya; burada UnRAR ile fark, kopyanın `memmove` kalitesine bağlı.

### 4.5 Pencere: ring mi, düz çıktı tamponu mu?
- **Non-solid ve dosya <= sözlük**: pencere = çıktı tamponu. Çıktıyı doğrudan nihai (yazma için ayrılmış) tampona çöz; ikinci kopya yok. rars bunu yapmıyor (pending + history).
- **Büyük dosya / solid**: `dict` boyutunun üstü 2'nin kuvveti ring + sonda "tekrar eden" kuyruk payı. Alternatif: büyük düz tampon + dilim başına `memmove` (zstd "prefix" yaklaşımı): dict büyükse pahalı; ring tercih. Ring'de eşleşme kopyası sarma kontrolü: mesafe <= konum ise sarmasız hızlı yol (çoğunluk), aksi halde yavaş yol (<%1 eşleşme [tahmin]).
- **Büyüme**: pencere çıktı yazıldıkça büyüsün (ikiye katlayarak, `dict`'e kadar); 4 GB sözlüklü arşivde 4 GB'lık sanal tahsis yapmadan (Windows commit charge). Güvenlik limiti: çağıranın verdiği `max_window`.
- Sink'e verilen dilimler pencereden (<= 2 dilim); sink hash/yazma için kopyalar yerine **tampon havuzu** + `Arc<[u8]>` devri.

### 4.6 Sınır denetimi ve `unsafe`
- İlk sürüm tamamen safe: tablolar sabit boyutlu diziler (`[u32; 1<<11]`) ve indeks maske ile sınırlı -> derleyici denetimi atar; girdi için "güvenli bölge" döngüsü (`while in_pos + 16 <= len && out_pos + SLACK <= cap`) içinde dilim dönüşümü bir kez `&[u8; 16]`/`try_into` ile.
- `unsafe` yalnızca ölçümle gerekçelendirilirse: (1) hızlı döngüde `get_unchecked` ile çıktı yazma/okuma, (2) 16/32 B genişletilmiş kopya (`ptr::copy_nonoverlapping` sarılmış). 3 fonksiyonla sınırlı bir modül (`fastcopy`), `#![forbid(unsafe_code)]` diğer her yerde, Miri + fuzz zorunlu. Beklenen kazanç: safe sürüme göre %5-15 [tahmin].

### 4.7 Filtreler
- **Önemli**: RAR filtreleri çıktıya uygulanır, **pencere filtrelenmemiş veriyi tutar**. Yani filtre bir kopya üzerinde çalışır -> filtre aşaması doğal olarak ayrı iş parçacığına uygun (çözücü sonraki bloğa devam ederken).
- E8/E8E9: kaydıran tarama; SIMD (`_mm256_cmpeq_epi8` + `movemask`) ile 0xE8/0xE9 bul, yalnızca bulunanlara dokun. Skaler ~1-2 GB/s -> SIMD 8-15 GB/s [tahmin]. Rars'taki `e8e9_decode` skaler bir döngüdür.
- DELTA (kanal başına önceki değer toplamı): kanal sayısı 1 iken seri bağımlılık; SIMD prefix-sum (shuffle tabanlı) 3-6 GB/s [tahmin]; kanal >= 2'de doğal paralel.
- ARM: BL komutlarına ofset; basit, vektörleştirilebilir.
- Ölçüm: normal arşivde 40.5 MB filtre = 0.03 s; yani rars bile %2. Gerçek exe-ağırlıklı arşivde (ör. 2 GB oyun dizini) payı artar ama çözmenin altında kalır.

### 4.8 Hash ve şifreleme
- CRC32: `crc32fast` (PCLMULQDQ) zaten >20 GB/s; yazma iş parçacığında yapılır. Ölçüm: 400 MB 0.01 s.
- BLAKE2sp: RAR5'te isteğe bağlı (`-ht`); varsayılan CRC32. Uygulama: `blake2s_simd` (MIT) crate'inde `blake2sp` var (8 yollu, AVX2) ~2-4 GB/s [tahmin]; 8 yaprak bağımsız -> yaprak başına iş parçacığıyla paralel de olur. Boru hattında çözücünün yanı sıra çalışır, kritik yol dışında.
- AES-NI + PBKDF2 maliyeti bölüm 1.3'te. Şifreli ve **solid** arşivde AES-CBC çözme (paralel yapılabilir) kritik yol değil: çözme AES'ten yavaş.

### 4.9 Paralellik: solid arşivde bile (ana öneri)
Gözlem: RAR5 sembol ayrıştırmasının (Huffman çözme, uzunluk/mesafe hesabı) **çıktı verisinden bağımsız** olması (bu oturumda ablasyonda doğrulandı: eşleşme kopyası yerine sıfır-doldurma koyunca çözme akışı sürdü). Bağımlılık: bloklar arası yalnızca `reps[4]`, `last_length` ve devralınan tablolar (tablolar bloğun kendi başlığında ya da "önceki bloğunki"). Dolayısıyla:

- **Aşama A (komut ayrıştırma)**: blok başlıklarını yürüyerek (başlıklar birkaç bayt, bloklar bayt boyutlu -> blok sınırları ucuz bulunur) blokları işçi iş parçacıklarına dağıt. Her işçi bloğu `Komut` dizisine çevirir: `Literal(run)`, `Match{len, dist}`, `Rep{slot, len}` (rep slotu sembolik), `Filter{...}`.
- **Rep düzeltme**: blok başındaki rep başvurularını (nadir, yalnızca ilk birkaç komut) sıralı geçişte gerçek mesafelere çözer; rep LRU güncellemesi ucuz. Alternatif: A'yı iki turlu yapmak yerine bir işçi bloğu bitirince bir sonraki bloğun `reps` başlangıç durumunu hesaplayacak kadar kısa "ön tarama".
- **Aşama B (LZ uygulama)**: tek iş parçacığı, komut dizilerini sırayla pencereye uygular (literal kopyası + eşleşme kopyası). Bellek-bağlı; ölçülen işte payı küçük (<%10-20) -> asıl darboğaz Aşama A paralelleşince B kalır.
- Aşama C: filtre/hash/yazma iş parçacıkları.
- Beklenen: A işi tek iş parçacığında ~1.2-1.4 s (rars) / ~0.4-0.5 s (hedef lean); 4 işçiyle ~0.1-0.15 s; B ~0.15-0.25 s; toplam ~0.25-0.35 s <- UnRAR'ın 0.94 s'sinin ~3x altı [tahmin; B'nin komut dizisi bellek trafiği ve iş parçacığı senkronizasyonu doğrulanmalı].
- **Riskler/doğrulanacaklar**: (1) WinRAR'ın blok boyutu: büyük bloklar (ör. birkaç MB paketli) paralellik granülünü bozmaz ama az blokta paralellik sınırlı; (2) blok başında "tablolar yok" (devralma) durumunda A işçisi önceki bloğun tablosunu bilmeli -> tablo bloğu zinciri sıralı (tablolar ucuz: başlıkta okunur), çözme paralel; (3) komut dizisi belleği: 85 M komut x 8 B = 680 MB! -> **pencere/blok başına akış** (boru hattı: A blok k+W'yi bitirirken B blok k'yı uygular, sınırlı kuyruk; ~16 blok = 1 MB komut), (4) Filtre kayıtları komut dizisinde konumla birlikte taşınır. (5) Kısa arşivlerde iş parçacığı başlatma maliyeti -> eşik (ör. paketli < 4 MB tek iş parçacığı).
- Bu fikir **orijinal olarak bu raporda önerilmektedir**; benzer bir yapı zstd çok iş parçacıklı çözmede ve "parallel Huffman" literatüründe var (bağımsız blok), ama RAR'ın solid durumunda "ayrıştırma bağımsız, uygulama bağımlı" ayrımı kullanılıyor. Kullanım öncesi küçük bir prototiple doğrulanmalı.

### 4.10 Uçtan uca boru hattı (solid/ non-solid ortak)
```
[okuma: mmap/ReadFile ileri-okuma + AES-CBC çözme]
   -> [çözme (A: komut ayrıştırma xN)  ->  B: LZ uygulama]
   -> [filtre + CRC/BLAKE2sp]  -> [yazıcı: dosya başına, çoklu bekleyen WriteFile]
```
- Sınırlı kanallar (1-4 MiB parçalar), tampon havuzu (tahsis yok), çift tamponlama, iptal bayrağı blok başına (~100 µs aralıkla; rars'taki sembol başına kontrolden 1000x seyrek).
- Disk yazma [ölçüm 1.2 GB/s sync dahil]: dosyayı bilinen boyutla önceden ayır (`SetEndOfFile`/`FILE_ALLOCATION_INFO`), `FILE_FLAG_SEQUENTIAL_SCAN`, tek büyük yazma; çok sayıda küçük dosyada **dosya oluşturma** baskın (Windows Defender gerçek zamanlı tarama): dosya oluşturmayı birkaç iş parçacığına yay.
- Non-solid: dosya başına bağımsız -> iş parçacığı havuzu (rars bunu yapıyor ve zaten UnRAR'dan hızlı: 0.60 vs 1.06 s).
- Çözücü dışı %20-30 yükü (3.4) bu mimariyle doğrudan hedeflenir: sıfır kopya sink, tahsis havuzu.

### 4.11 Uygulama karşılaştırması
| | rars 0.12.3 | libarchive rar5.c (okunmadı; bilinen) | compcol rar5 | rar-codec |
|---|---|---|---|---|
| Lisans | Apache-2.0 | BSD-2 | MIT | Apache-2.0 |
| Bit okuyucu | bit konumu + 3 B dilim | (C, 32/64 bit tampon varsayımı, doğrulanmadı) | 16-bit peek | `acc = acc<<8 \| b` döngüsü |
| Huffman | 10-bit hızlı + döngü | tablo sorgu | 9-bit birincil | `DecodeTable` + uzun kod |
| Pencere | VecDeque + pending | ring | ring (pow2) | ring (pow2) |
| Çıktı yolu | çift kopya | - | pending + drain | `out` Vec |
| Paralellik | dosya başına | yok | yok | yok |
| Hız (solid) | 226 MB/s [ölçüm] | ölçülmedi | ölçülmedi | 232 MB/s [ölçüm] |
| Yetenek | tam okuma+yazma, RAR1-5, şifre, kurtarma | RAR3/5 okuma | yalnızca çözücü (RAR1-5; kapsayıcı yok) | RAR3/5 okuma |

---

## 5. UnRAR C++'ı geçebilir miyiz? Dürüst değerlendirme

Taban çizgisi [ölçüm]: UnRAR solid 427 MB/s, non-solid 377 MB/s uçtan uca (CRC dahil, bellek sink'i).

| Senaryo | Hedef (tek iş parçacığı) | Hedef (çok iş parçacığı) | Güven |
|---|---|---|---|
| Non-solid çözme | 450-600 MB/s/çekirdek [tahmin] | 2-3 GB/s (disk/ bellek sınırlı) | Yüksek: zaten rars paralel UnRAR'ı geçiyor |
| Solid, **çözücü çekirdeği** | 500-800 MB/s [tahmin] (5-7 ns/komut) | A/B ayrımıyla 1.2-2 GB/s [tahmin] | Orta: A/B ayrımı doğrulanmadı |
| Solid, **uçtan uca disk yazma dahil** | UnRAR'a eşit - 1.3x | 1.5-3x | Orta; disk/NTFS/Defender tavanı belirler |
| Şifreli (AES) | AES-NI + paralel çözme: çözme baskın kalır, UnRAR ile eşit-1.2x | | Orta |
| PPMd (RAR3) | **UnRAR'a eşit hedef**, geçmek zor | | Düşük-orta |
| RAR3 LZ+VM filtre | RAR5 LZ'ye benzer, standart filtreleri doğal kodla -> eşit-1.3x | | Orta |

Dürüstlük notları:
- UnRAR C++ elle ayarlanmış, ölçülen komut başına ~11 ns uçtan uca; tek iş parçacığında bir Rust çözücünün bunu aşması "kolay" değil: libdeflate sınıfı bir çözücü ve ön-işlenmiş tablolar gerektirir. Tahminim: tek iş parçacığında **eşitliğe yakın - 1.3x**; "asla yavaş değil" hedefi için tek iş parçacığı yeterli değil, **boru hattı + solid-içi paralel A aşaması** ile kazanç kesinleşir.
- Ölçüm arşivleri rars'ın seviye 1 çıktısı; WinRAR arşivlerinde (uzun eşleşme, daha çok rep, uzak mesafe -> cache ıskalaması) iki taraf da farklı hızda; **oran** belirsiz. Mutlaka gerçek arşivle yeniden ölç (6.4).
- Tek çekirdekli/ yavaş disk makinelerinde fark iş parçacıklarına bağlı olmaktan çıkar: "asla daha yavaş değil" yalnızca tek iş parçacığı çekirdeği UnRAR'a eşitse güvence altındadır -> **ana kapı: tek iş parçacığı çözme <= UnRAR** (varsayımsal en kötü durum: 1 çekirdek).

---

## 6. Önerilen mimari

### 6.1 Crate düzeni (workspace `rarchive/`)
| Crate | İçerik | Notlar |
|---|---|---|
| `rarchive-core` | G/Ç'siz çözücüler: bit okuyucu, Huffman, RAR5 LZ, (sonra) RAR3 LZ/PPMd, filtreler, pencere, hash arayüzleri | `no_std + alloc` uyumlu; `#![forbid(unsafe_code)]` çekirdek; `fastcopy` modülü ayrı feature (`unsafe-fast`) |
| `rarchive-format` | RAR4/RAR5 başlık ayrıştırıcıları, vint, QO/locator, uzantı kayıtları | yalnızca `&[u8]`/`ReadAt` |
| `rarchive-crypto` | AES-CBC, PBKDF2-HMAC-SHA256, SHA-1 KDF, KDF önbelleği | `aes`, `sha2`, `sha1`, `hmac`, `zeroize` |
| `rarchive-io` | Kaynak türleri (dosya/mmap/bellek), çok parçalı birleştirme, Windows dosya yazıcı (önceden ayırma, async), boru hattı | |
| `rarchive` | Cephe API (liste, çıkar, ilerleme/iptal) | |
| `rarchive-cli` | `rarchive l`, `x`, `t`, `bench` | |
| `fuzz/` | cargo-fuzz hedefleri | |
| `rarchive-tests/` | korpus testleri, diferansiyel testler | |

### 6.2 Akışlı API şekli (dosya yöneticisi için)
```rust
let ar = Archive::open(source, OpenOptions { password_cb, max_window, limits })?;
for e in ar.entries() { /* ad, boyut, paketli, crc, dizin?, solid?, şifreli?, yöntem, mtime, attr, yönlendirme */ }
ar.entries_quick()           // QO varsa hızlı liste; kullanılırsa çıkarma da aynı kaynaktan (teknote güvenlik notu)

// tek dosya (solid ise önceki üyeleri sink'siz "atlama çözmesi" ile geçer; maliyet tahmini sunar)
ar.extract(entry_id, &mut dyn Sink, &mut dyn Progress)?;

// hepsi
ar.extract_all(&mut dyn SinkFactory, ExtractOptions { threads, ..})?;

trait SinkFactory { fn begin(&mut self, e:&Entry) -> Decision<Box<dyn FileSink>>; } // Skip / Write / Abort
trait FileSink: Send { fn write(&mut self, buf:&[u8])->io::Result<()>; fn finish(self:Box<Self>, v:Verified)->io::Result<()>; }
trait Progress { fn update(&mut self, p:&Info) -> Control; } // Continue | Cancel
```
- **Hiçbir zaman üzerine yazma politikası çağırana bırakılır** (`begin` Skip döner; kütüphane dosya sistemine kendisi dokunmaz; CLI varsayılanı "yeniden adlandır").
- Atlama çözmesi: solid arşivde atlanan üyeler için hash ve yazma yapılmaz, yalnızca pencere ilerler.
- Hatalar: tür belirleyici enum (`WrongPassword`, `CorruptHeader`, `ChecksumMismatch{entry}`, `LimitExceeded`, `Unsupported(feature)`), kısmi çıktı sink'e `finish(Verified::Failed)` ile bildirilir.

### 6.3 Güvenlik duruşu
- Fuzzing: `cargo-fuzz` (nightly, libFuzzer; Windows MSVC'de çalışır ama ASan sınırlı -> Linux CI ya da WSL tercih). Hedefler: başlık ayrıştırıcı, Huffman tablo kurucu, RAR5 çözücü (rastgele blok + durumlu), filtre uygulayıcı, RAR3 PPMd. Çevrimdışı diferansiyel fuzz: UnRAR ikili/`unrar` crate'ini **yalnızca çalıştırarak** oracle olarak (çıktı + hata/başarı karşılaştırması; kaynağına bakmadan).
- Sınırlar (bomba koruması): `max_window` (varsayılan 1 GiB, çağıran ayarlar), toplam açılmış boyut/oran sınırı (ör. 1000:1 + mutlak üst sınır opsiyonel), başlık <= 2 MiB (teknote), girdi/kayıt sayısı, filtre sayısı ve filtre bloğu <= 4 MiB, ad uzunluğu, iç içe dizin derinliği, KDF yineleme tavanı (log2 <= 24 gibi; RAR "sürüme bağlı eşik" der).
- Yol güvenliği (zip-slip): `..`, mutlak yol, sürücü harfi, `:` (ADS), ayrılmış adlar (CON/NUL...), sondaki nokta/boşluk, **symlink/junction yönlendirme kayıtlarını varsayılan reddet**; çıkarma kök dizini dışına çıkış yasak.
- `unsafe` denetimi: tek modül, Miri, fuzz, ayrı CI işi.

### 6.4 Test korpusu stratejisi (WinRAR kurulu olmadan)
1. **libarchive test dosyaları**: `libarchive/test/test_read_format_rar*.rar.uu`, `test_read_format_rar5_*.rar.uu` (uuencode; BSD-2 deposu içinde). Lisans: deponun test verisi için ayrıca istisna yok; BSD-2 kapsamında yeniden dağıtım atıf ister; **kullanmadan önce libarchive COPYING'i ve dosya başlıklarını kontrol et** [doğrulanmadı]. Çeşitli (store, LZ, PPMd, filtre, şifreli, çok parçalı, ARM filtre vb.) gerçek WinRAR üretimi arşivler içerir — **en değerli kaynak**.
2. `rars` fixture'ları (`tests/rar50_fixtures.rs`, `rar15_40_fixtures.rs`; Apache-2.0) ve `bitplane/rar-research` spec/test deposu (lisans kontrol edilecek).
3. Üreticiler: `rars` yazıcısı (RAR5 ve RAR4 yazabilir; PPMd/ VM varsa). **Uyarı**: kendi kodlayıcısı ile kendi çözücüsünü test etmek hata gizler; diferansiyel test için UnRAR oracle'ı kullan.
4. Gerçek, kamuya açık arşivler: Linux/BSD paket depoları, Internet Archive, GitHub sürüm dosyaları (**lisans/telif denetimi**; yalnızca test için ve depoya değil CI indirme betiğiyle).
5. **Performans korpusu**: en az 3 gerçek WinRAR arşivi (solid + non-solid; exe ağırlıklı, metin ağırlıklı, medya ağırlıklı) — kullanıcının makinesinde WinRAR ile **kendisi** üretebilir (bizim kurulum yapmamız gerekmez); yoksa trial. Bunlar depoya konmaz, boyut büyük.
6. Rastgele/sentetik: rars ile üretilen arşivler (hızlı regresyon), `proptest` ile bit-düzeyi round-trip.
7. Her PR'da: `unrar` (oracle) ile tüm korpus çıktı özeti (CRC32/BLAKE2sp) karşılaştırması.

### 6.5 Fazlı plan ve ölçülebilir çıkış kriterleri
| Faz | İçerik | Çıkış kriteri |
|---|---|---|
| 0 | Hızlı çekirdek spike'ı: RAR5 LZ çözücü (rars blok ayrıştırıcısı + kendi bit okuyucu/tablolar) ve 3 gerçek WinRAR arşivi | mevcut harness solid: çözücü fonksiyonu <= 0.9 s; komut başına <= 8 ns |
| 1 | RAR5 kapsayıcı + store | `l`/`x` store arşivde UnRAR çıktısıyla bayt-bayt eşit; store çıkarma >= UnRAR |
| 2 | RAR5 LZ (non-solid) | tek iş parçacığı: normal arşiv UnRAR'ın <= 1.0x süresi; paralel: <= 0.6 x UnRAR |
| 3 | Filtreler (DELTA, E8, E8E9, ARM) | filtreli arşiv + oracle eşitliği; E8 SIMD >= 5 GB/s |
| 4 | Solid + boru hattı (+ A/B ayrımı spike) | solid uçtan uca <= 0.9 x UnRAR (tek iş parçacığı çözücü) ve <= 0.5 x (çok iş parçacığı) |
| 5 | Şifreleme (RAR5: AES-256+PBKDF2, başlık şifreleme, KDF önbelleği) | doğru/yanlış parola, şifreli arşivde <= 1.2 x UnRAR |
| 6 | Çok parçalı (volume) | ayrık + birleşik çıktı eşit, kesilmiş volume hatası |
| 7 | RAR3/4 (LZ+VM standart+PPMd, AES-128) | tüm libarchive RAR3 korpusu eşit; LZ <= UnRAR, PPMd <= 1.1 x UnRAR |
| 8 | RAR7 (algoritma v1, büyük sözlük) | RAR7 arşivleri (varsa) eşit; 1-4 GB sözlük bellek davranışı sınırlı |
| 9 | Kurtarma kaydı doğrulama/onarım, quick-open | `l` hızı (büyük arşivde başlık tarama yok) |
| 10 | Yazıcı (yalnızca store → sonra düşünülecek, hukuki inceleme) | bkz. 7 |
| 11 | RAR2/1.5, fuzz sertleştirme | 24 saat fuzz çökmeden |

---

## 7. Clean-room / lisans notları

**Kullanılabilir (atıfla):**
- `rars` (Apache-2.0): kod okumak serbest; kod kopyalarsak NOTICE/atıf (Apache §4: lisans kopyası, değişiklik bildirimi, NOTICE). Plan: kod kopyalamamak, davranışı doğrulamak için okumak. Sabit/tablolar (yuva formülleri, düzen) olgu niteliğinde.
- libarchive (BSD-2): atıf (telif bildirimi + lisans metni), test dosyaları.
- `compcol` (MIT), `rar-codec` (Apache-2.0): aynı.
- Fikirler: libdeflate (Eric Biggers; MIT), zstd/huff0 (BSD/GPL ikili), Giesen blogu, Bloom blogu, `zune-inflate` (MIT/Apache/Zlib), `miniz_oxide`.
- Rust crate bağımlılıkları: `crc32fast`, `aes`, `sha2`, `sha1`, `hmac`, `blake2s_simd` (hepsi MIT/Apache).

**UnRAR lisansı (RARLAB):** (genel bilgi, kaynak metne bakılmadı) UnRAR kaynağı, RAR arşivlerini açma yazılımı geliştirmek için kullanılabilir ama **"RAR sıkıştırma algoritmasını yeniden oluşturmak için kullanılamaz"**. `compcol` belgesi (rar5/mod.rs) bunu aynen belirtiyor ve libarchive/The Unarchiver'ın yalnızca çözücü sunduğunu not ediyor. Biçimi teknote'tan uygulamak ve çözücüyü clean-room yazmak yaygın uygulamadır (libarchive, 7-Zip, The Unarchiver). **Yazıcı (kodlayıcı) için**: UnRAR kaynağını kullanmadan, kendi tasarımıyla yazmak RARLAB lisansının kapsamı dışında olabilir (rars bunu yapıyor), ama bu hukuki bir risk alanı; **v1 yalnızca çözücü**; yazıcı ancak "store" yöntemi (sıkıştırmasız, tamamen sıradan kapsayıcı) için düşünülür, LZ yazıcısı hukuki inceleme gerektirir. Bu bir hukuki tavsiye değildir.

**Provenance (köken) günlüğü:** her sabit/formül/bit düzeni için "kaynak: teknote §x / rars dosya:satır / libarchive fonksiyon" kaydı tutulacak (`docs/rarchive/provenance.md`). rars'ın kendi kaynağının kökeni (spec deposu `bitplane/rar-research`) bu oturumda doğrulanmadı; o depo UnRAR'dan türemiş çıktı içeriyorsa kullanmayız. rar-codec'in depo kökeni (`danalec/rgx`) belirsiz: UnRAR portu olup olmadığı doğrulanmadığı için **içeriğini kaynak olarak kullanmama** ya da başlık/yapı düzeyinde bile okumama kararı önerilir (bu oturumda yalnızca dosya adları, struct adları ve kısa grep yapıldı; algoritma okunmadı).

---

## 8. Açık sorular ve riskler
1. WinRAR üretimi arşivlerde blok boyutu, rep kullanımı, uzak mesafe oranı: A/B paralelliğinin getirisini belirler.
2. RAR7 algoritma sürümü 1'in mesafe tablosu dışında bir farkı var mı (rars `algorithm_version` kullanımı incelenecek).
3. Şifreli arşivde dosya başına tuz oranı (KDF önbelleği faydası).
4. Windows dosya oluşturma maliyeti (Defender) ve G/Ç stratejisi: ölçülmeli (küçük dosya yüklü arşiv: 50k dosya).
5. `rar-codec` ve `rars` spec deposunun köken denetimi.
6. Çok çekirdekli kazançların düşük çekirdekli (2-4 çekirdek) makinelerde doğrulanması.

## 9. Ekler
- Ölçüm araçları (kopya, depo dışı): `rars-prof` (sayaçlı rars kopyası), `rarprof` (ölçüm programı), arşivler `bt/bench*.rar` (115 MB x2; ihtiyaç bitince silinebilir).
- Kaynaklar: https://www.rarlab.com/technote.htm ; `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/rars-0.12.3/src/codec/rar50.rs` (satır 143-380, 963-1120, 1285-1512, 1969-2240), `.../src/crypto/rar50.rs`, `.../src/crc32/mod.rs` ; `.../compcol-0.7.8/src/rar5/mod.rs` ; https://github.com/bitplane/rars ; https://github.com/bitplane/rar-research ; libdeflate (Eric Biggers) decompress_template.h ; Fabian Giesen, "Reading bits in far too many ways" (fgiesen.wordpress.com 2018) ; Charles Bloom blog (cbloomrants.blogspot.com, Huffman/LZ çözme) ; zstd `huf_decompress.c`.
