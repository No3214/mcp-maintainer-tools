# AGENTS.md

<!-- ORTAK-KURALLAR:begin -->
## Ortak kurallar (tüm LLM ajanları için bağlayıcı) — v2 · 2026-11-02

Bu depoda çalışan her ajan (Codex/Astra, Claude Code, Fable, Kimi, Gemini/Argon, Muse, Cursor, Copilot, Grok Bot, llm-council) önce kanonik kural dosyasını okur:
**`No3214/ortak-kayit` → `KURALLAR-KANONIK.md`** (56 kural; https://github.com/No3214/ortak-kayit/blob/main/KURALLAR-KANONIK.md). Bu blok yalnız özettir; çelişkide kanonik dosya ve sahibin son talimatı kazanır.

En kritik 14 kural:
1. Yunuscan'a her mesaj Türkçe; önce sonuç, ama iş eksiksiz ve ayrıntılı.
2. Geri alınabilir işte kararı ajan verir; eksik girdiyi ajan kendisi bulur.
3. Her işte llm-council; yalnız gerçekten koşan üyeler yazılır, koşmayan NOT_RUN + neden. Özel veri yalnız özel üyelere (astra, fable_native, kimi, argon, flash38, muse).
4. Model yönlendirme: orkestratör Astra 6 high + Fable 5.1 high; işçi kimi k3.1-pro max; Grok canlı bilgi + ikinci kontrol (yalnız Grok Bot aboneliği); Jev toplu filtre; kodlama Claude Opus 5.5 high; bu paket varken ücretsiz LLM yok; ücretli API yok.
5. Resmi puan 31,4; sahte puan, uydurma sayı, kanıtsız "bitti" yok. Bilinmeyen `[VERİ_YOK]`.
6. Her koşuda girdi/çıktı uzlaştırma, hash, komut + çıkış kodu, eksik listesi.
7. 01.11.2026 itibarıyla odak yalnız dijital reklam + ajans; `No3214/branding` birinci öncelik.
8. ODAKRA bırakıldı (01.11); ODAKRA içeriği silinmez ama aktif iş gibi gösterilmez.
9. Eski ajans adı ("Evolution" ile başlayan eski ad) kullanılmaz; yeni ad uydurulmaz, kesin karar Yunuscan'da.
10. `main`'e doğrudan push, force push, geçmiş yeniden yazma, uzak dal silme yok; yeni iş = dal + taslak PR; merge Yunuscan'da.
11. Sır ve hassas veri (müşteri/konuk kaydı, token, parola, çerez) depoya yazılmaz; commit öncesi gitleaks + regex.
12. Dış mesaj yalnız taslak; yayın, harcama, izin genişletme, giriş/captcha aşma yok; sudo yok; silme yalnız son onayla.
13. Instagram yalnız okuma (takip/takipten çıkma/beğeni/gönderi/mesaj yok).
14. Orkestratör paketleri yalnız Yunuscan "başlat" yazınca yürür.
<!-- ORTAK-KURALLAR:end -->
