# Αναφορά Ανάλυσης Ασφάλειας WebGoat

## Σύνοψη

Η παρούσα αναφορά τεκμηριώνει κρίσιμες ευπάθειες ασφαλείας που εντοπίστηκαν στην εφαρμογή WebGoat μέσω στατικής ανάλυσης κώδικα με χρήση του εργαλείου CodeQL. Η ανάλυση αποκάλυψε 6 ευπάθειες υψηλής σοβαρότητας που θα μπορούσαν να οδηγήσουν σε σοβαρές παραβιάσεις ασφαλείας εάν εκμεταλλευτούν σε περιβάλλον παραγωγής.

## Πίνακας Περιεχομένων
1. [Επισκόπηση Ευπαθειών](#επισκόπηση-ευπαθειών)
2. [Λεπτομερής Ανάλυση Ευπαθειών](#λεπτομερής-ανάλυση-ευπαθειών)
3. [Αξιολόγηση Τεχνικών Επιπτώσεων](#αξιολόγηση-τεχνικών-επιπτώσεων)
4. [Οδηγίες Αποκατάστασης](#οδηγίες-αποκατάστασης)
5. [Μεθοδολογία Ελέγχου](#μεθοδολογία-ελέγχου)
6. [Παράρτημα](#παράρτημα)

## Επισκόπηση Ευπαθειών

### Σύνοψη Ευρημάτων

| Προτεραιότητα | Τύπος Ευπάθειας | CWE ID | OWASP Top 10 | Επηρεαζόμενα Αρχεία | Επίπεδο Κινδύνου |
|---------------|-----------------|---------|---------------|---------------------|------------------|
| 1 | Μη Ασφαλής Αποσειριοποίηση | CWE-502 | A08:2021 | DeserializeTask.java | Κρίσιμο |
| 2 | XML External Entity (XXE) | CWE-611 | A05:2021 | CommentsCache.java | Κρίσιμο |
| 3 | Server-Side Request Forgery (SSRF) | CWE-918 | A10:2021 | SSRFTASK2.java | Κρίσιμο |
| 4 | Zip Slip Path Traversal | CWE-22 | A01:2021 | ProfileZipSlip.java | Υψηλό |
| 5 | Μη Ελεγχόμενη Έκφραση Διαδρομής (FileServer) | CWE-73 | A03:2021 | FileServer.java | Υψηλό |
| 6 | Μη Ελεγχόμενη Έκφραση Διαδρομής (XXE Module) | CWE-73 | A03:2021 | BlindSendFileAssignment.java | Υψηλό |

### Στιγμιότυπο: Πίνακας Ελέγχου CodeQL
[Πίνακας ελέγχου CodeQL που εμφανίζει όλες τις ευπάθειες](https://github.com/Marilenaki/computer-security-and-data-protection/blob/main/docs/codeql.jpeg)

## Λεπτομερής Ανάλυση Ευπαθειών

### 1. Μη Ασφαλής Αποσειριοποίηση Δεδομένων Χρήστη

**Τοποθεσία:** `src/org/owasp/webgoat/plugin/serialization/DeserializeTask.java`

**Τεχνική Περιγραφή:**
Η εφαρμογή δέχεται σειριοποιημένα αντικείμενα Java από μη αξιόπιστες πηγές και τα αποσειριοποιεί χωρίς κατάλληλη επικύρωση. Αυτή η ευπάθεια επιτρέπει σε επιτιθέμενους να εκτελέσουν αυθαίρετο κώδικα δημιουργώντας κακόβουλα σειριοποιημένα αντικείμενα.

**Ευάλωτο Μοτίβο Κώδικα:**
```java
public Object deserializeUserInput(byte[] serializedData) {
    ByteArrayInputStream bais = new ByteArrayInputStream(serializedData);
    ObjectInputStream ois = new ObjectInputStream(bais);
    return ois.readObject(); // Επικίνδυνο - χωρίς επικύρωση
}
```

**Σενάριο Επίθεσης:**
Ένας επιτιθέμενος μπορεί να δημιουργήσει ένα σειριοποιημένο αντικείμενο που περιέχει κακόβουλα φορτία χρησιμοποιώντας αλυσίδες gadget από βιβλιοθήκες που υπάρχουν στο classpath (π.χ., Apache Commons Collections). Όταν αποσειριοποιηθούν, αυτά τα αντικείμενα μπορούν να εκτελέσουν εντολές συστήματος, να διαβάσουν ευαίσθητα αρχεία ή να δημιουργήσουν reverse shells.

---

### 2. XML External Entity (XXE) Injection

**Τοποθεσία:** `src/org/owasp/webgoat/plugin/xxe/CommentsCache.java`

**Τεχνική Περιγραφή:**
Ο αναλυτής XML είναι ρυθμισμένος χωρίς να απενεργοποιεί την επίλυση εξωτερικών οντοτήτων, επιτρέποντας σε επιτιθέμενους να συμπεριλάβουν εξωτερικές οντότητες στην είσοδο XML. Αυτό μπορεί να οδηγήσει σε αποκάλυψη ευαίσθητων αρχείων, επιθέσεις SSRF ή άρνηση υπηρεσίας.

**Ευάλωτο Μοτίβο Κώδικα:**
```java
public Document parseXML(String xmlInput) {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    // Λείπουν ρυθμίσεις ασφαλείας
    DocumentBuilder builder = factory.newDocumentBuilder();
    return builder.parse(new InputSource(new StringReader(xmlInput)));
}
```

**Παράδειγμα Διανύσματος Επίθεσης:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<comment>
  <text>&xxe;</text>
</comment>
```

**Στιγμιότυπο: Λεπτομέρειες Ευπάθειας XXE**
[Ροή κώδικα ευπάθειας XXE](https://github.com/Marilenaki/computer-security-and-data-protection/blob/main/docs/1.jpeg)

---

### 3. Server-Side Request Forgery (SSRF)

**Τοποθεσία:** `src/org/owasp/webgoat/plugin/ssrf/SSRFTASK2.java`

**Τεχνική Περιγραφή:**
Η εφαρμογή δέχεται URLs ελεγχόμενα από τον χρήστη και πραγματοποιεί HTTP αιτήματα σε αυτά χωρίς κατάλληλη επικύρωση. Αυτό επιτρέπει σε επιτιθέμενους να κάνουν τον διακομιστή να ζητήσει εσωτερικούς πόρους, cloud metadata endpoints ή να εκτελέσει σάρωση θυρών.

**Ευάλωτη Υλοποίηση:**
```java
public String fetchURL(String userProvidedURL) {
    URL url = new URL(userProvidedURL); // Χωρίς επικύρωση
    URLConnection connection = url.openConnection();
    return readResponse(connection);
}
```

**Παραδείγματα Εκμετάλλευσης:**
- Πρόσβαση σε εσωτερικές υπηρεσίες: `http://localhost:8080/admin`
- Cloud metadata: `http://169.254.169.254/latest/meta-data/`
- Σάρωση εσωτερικού δικτύου: `http://192.168.1.1:22`

**Στιγμιότυπο: Ροή Επίθεσης SSRF**
[Θέση για στιγμιότυπο: Επίδειξη ευπάθειας SSRF](https://github.com/Marilenaki/computer-security-and-data-protection/blob/main/docs/ssrf.jpeg)

---

### 4. Zip Slip Path Traversal

**Τοποθεσία:** `src/org/owasp/webgoat/plugin/pathtraversal/ProfileZipSlip.java`

**Τεχνική Περιγραφή:**
Η εφαρμογή εξάγει αρχεία ZIP χωρίς να επικυρώνει τη διαδρομή προορισμού κάθε καταχώρησης. Κακόβουλα αρχεία ZIP μπορούν να περιέχουν καταχωρήσεις με ακολουθίες διάσχισης καταλόγου (../) που γράφουν αρχεία εκτός του προβλεπόμενου καταλόγου.

**Ευάλωτη Λογική Εξαγωγής:**
```java
public void extractZip(File zipFile, File destDir) {
    ZipInputStream zis = new ZipInputStream(new FileInputStream(zipFile));
    ZipEntry entry;
    while ((entry = zis.getNextEntry()) != null) {
        File newFile = new File(destDir, entry.getName()); // Μη ασφαλής συνένωση
        // Το αρχείο γράφεται χωρίς επικύρωση διαδρομής
        writeFile(newFile, zis);
    }
}
```

**Επίπτωση Επίθεσης:**
- Αντικατάσταση αρχείων συστήματος
- Τοποθέτηση κακόβουλων scripts σε καταλόγους web
- Τροποποίηση αρχείων ρυθμίσεων εφαρμογής

---

### 5. Μη Ελεγχόμενη Έκφραση Διαδρομής - FileServer

**Τοποθεσία:** `src/org/owasp/webgoat/webwolf/FileServer.java`

**Τεχνική Περιγραφή:**
Η είσοδος χρήστη χρησιμοποιείται απευθείας για την κατασκευή διαδρομών αρχείων χωρίς κατάλληλη εξυγίανση. Αυτό επιτρέπει σε επιτιθέμενους να έχουν πρόσβαση σε αρχεία εκτός της προβλεπόμενης δομής καταλόγου χρησιμοποιώντας τεχνικές διάσχισης διαδρομής.

**Ευάλωτο Μοτίβο:**
```java
public File getRequestedFile(String filename) {
    String basePath = "/var/webgoat/files/";
    return new File(basePath + filename); // Απευθείας συνένωση
}
```

**Τεχνικές Εκμετάλλευσης:**
- Βασική διάσχιση: `../../../etc/passwd`
- URL κωδικοποίηση: `%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd`
- Διπλή κωδικοποίηση: `%252e%252e%252f`

---

### 6. Μη Ελεγχόμενη Έκφραση Διαδρομής - XXE Module

**Τοποθεσία:** `src/org/owasp/webgoat/plugin/xxe/BlindSendFileAssignment.java`

**Τεχνική Περιγραφή:**
Παρόμοια με την ευπάθεια του FileServer, αυτό το module δέχεται διαδρομές αρχείων ελεγχόμενες από τον χρήστη στο πλαίσιο του μαθήματος XXE. Η έλλειψη επικύρωσης εισόδου επιτρέπει επιθέσεις διάσχισης καταλόγου.

**Ανάλυση Κώδικα:**
```java
public String readFileContent(String filepath) {
    // Καμία επικύρωση της παραμέτρου filepath
    File file = new File(filepath);
    return Files.readString(file.toPath());
}
```

## Αξιολόγηση Τεχνικών Επιπτώσεων

### Ανάλυση Επιχειρηματικών Επιπτώσεων

| Ευπάθεια | Εμπιστευτικότητα | Ακεραιότητα | Διαθεσιμότητα | Συνολικός Κίνδυνος |
|----------|------------------|-------------|---------------|-------------------|
| Μη Ασφαλής Αποσειριοποίηση | Υψηλή | Υψηλή | Υψηλή | Κρίσιμος |
| XXE | Υψηλή | Μέτρια | Μέτρια | Κρίσιμος |
| SSRF | Υψηλή | Μέτρια | Χαμηλή | Κρίσιμος |
| Zip Slip | Μέτρια | Υψηλή | Χαμηλή | Υψηλός |
| Path Traversal (FileServer) | Υψηλή | Χαμηλή | Χαμηλή | Υψηλός |
| Path Traversal (XXE) | Υψηλή | Χαμηλή | Χαμηλή | Υψηλός |

### Πιθανές Αλυσίδες Επίθεσης

1. **Πλήρης Παραβίαση Συστήματος:**
   - Μη Ασφαλής Αποσειριοποίηση → Απομακρυσμένη Εκτέλεση Κώδικα → Πλήρης Πρόσβαση Συστήματος

2. **Αγωγός Εξαγωγής Δεδομένων:**
   - XXE → Ανάγνωση Αρχείων → SSRF → Εξωτερική Μεταφορά Δεδομένων

3. **Μόνιμη Backdoor:**
   - Zip Slip → Εγγραφή Web Shell → Διατήρηση Πρόσβασης

## Οδηγίες Αποκατάστασης

### Προτεραιότητα 1: Μη Ασφαλής Αποσειριοποίηση

**Άμεσες Ενέργειες:**
```java
// Αντικατάσταση με σειριοποίηση JSON
public Object parseUserData(String jsonData) {
    ObjectMapper mapper = new ObjectMapper();
    mapper.enableDefaultTyping(ObjectMapper.DefaultTyping.NON_FINAL, 
        JsonTypeInfo.As.PROPERTY);
    return mapper.readValue(jsonData, SafeObject.class);
}
```

**Μακροπρόθεσμη Λύση:**
- Υλοποίηση φιλτραρίσματος σειριοποίησης
- Χρήση λιστών επιτρεπόμενων κλάσεων
- Εξέταση εναλλακτικών μορφών δεδομένων (JSON, Protocol Buffers)

### Προτεραιότητα 2: Πρόληψη XXE

**Ασφαλής Ρύθμιση:**
```java
public Document parseXMLSecurely(String xml) {
    DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
    
    // Πλήρης απενεργοποίηση DTDs
    factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    
    // Απενεργοποίηση εξωτερικών οντοτήτων
    factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
    factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    
    // Απενεργοποίηση εξωτερικών DTDs
    factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
    
    factory.setXIncludeAware(false);
    factory.setExpandEntityReferences(false);
    
    DocumentBuilder builder = factory.newDocumentBuilder();
    return builder.parse(new InputSource(new StringReader(xml)));
}
```

### Προτεραιότητα 3: Μετριασμός SSRF

**Υλοποίηση Επικύρωσης URL:**
```java
public String fetchURLSecurely(String userURL) {
    URL url = new URL(userURL);
    
    // Λίστα επιτρεπόμενων πρωτοκόλλων
    if (!Arrays.asList("http", "https").contains(url.getProtocol())) {
        throw new SecurityException("Μη έγκυρο πρωτόκολλο");
    }
    
    // Αποκλεισμός ιδιωτικών IP
    InetAddress address = InetAddress.getByName(url.getHost());
    if (address.isSiteLocalAddress() || address.isLoopbackAddress()) {
        throw new SecurityException("Απορρίφθηκε πρόσβαση σε ιδιωτική IP");
    }
    
    // Υλοποίηση timeout και ορίων μεγέθους
    URLConnection conn = url.openConnection();
    conn.setConnectTimeout(5000);
    conn.setReadTimeout(5000);
    
    return readLimitedResponse(conn, 1024 * 1024); // Όριο 1MB
}
```

### Προτεραιότητα 4: Πρόληψη Path Traversal

**Ασφαλής Πρόσβαση Αρχείων:**
```java
public File getFileSecurely(String filename) {
    // Εξυγίανση ονόματος αρχείου
    String cleanName = filename.replaceAll("[^a-zA-Z0-9._-]", "");
    
    File baseDir = new File("/var/webgoat/files/").getCanonicalFile();
    File requestedFile = new File(baseDir, cleanName).getCanonicalFile();
    
    // Διασφάλιση ότι το αρχείο είναι εντός του βασικού καταλόγου
    if (!requestedFile.getPath().startsWith(baseDir.getPath())) {
        throw new SecurityException("Εντοπίστηκε απόπειρα path traversal");
    }
    
    return requestedFile;
}
```

### Προτεραιότητα 5: Προστασία Zip Slip

**Ασφαλής Εξαγωγή ZIP:**
```java
public void extractZipSecurely(File zipFile, File destDir) throws IOException {
    String destDirPath = destDir.getCanonicalPath();
    
    try (ZipInputStream zis = new ZipInputStream(new FileInputStream(zipFile))) {
        ZipEntry entry;
        while ((entry = zis.getNextEntry()) != null) {
            File destFile = new File(destDir, entry.getName());
            String destFilePath = destFile.getCanonicalPath();
            
            // Επικύρωση διαδρομής προορισμού
            if (!destFilePath.startsWith(destDirPath + File.separator)) {
                throw new SecurityException("Καταχώρηση zip εκτός στόχου: " + entry.getName());
            }
            
            if (entry.isDirectory()) {
                destFile.mkdirs();
            } else {
                destFile.getParentFile().mkdirs();
                Files.copy(zis, destFile.toPath(), StandardCopyOption.REPLACE_EXISTING);
            }
        }
    }
}
```

## Μεθοδολογία Ελέγχου

### Ρύθμιση Στατικής Ανάλυσης

**Σουίτα Ερωτημάτων CodeQL που Χρησιμοποιήθηκε:**
```yaml
name: "Ανάλυση Ασφάλειας WebGoat"
queries:
  - uses: security-and-quality
  - uses: security-extended
  - uses: security-experimental
```

### Βήματα Επαλήθευσης

1. **Έλεγχοι Πριν την Αποκατάσταση:**
   - Εκτέλεση ανάλυσης CodeQL
   - Τεκμηρίωση όλων των ευρημάτων
   - Δημιουργία proof-of-concept exploits

2. **Έλεγχοι Μετά την Αποκατάσταση:**
   - Επανεκτέλεση ανάλυσης CodeQL
   - Χειροκίνητη επισκόπηση κώδικα
   - Εκτέλεση δοκιμών διείσδυσης
   - Επικύρωση ελέγχων ασφαλείας

### Στιγμιότυπο: Αποτελέσματα Ελέγχων
[Θέση για στιγμιότυπο: Σύγκριση πριν και μετά την αποκατάσταση]

## Παράρτημα

### Αναφορές

- [CWE-502: Αποσειριοποίηση Μη Αξιόπιστων Δεδομένων](https://cwe.mitre.org/data/definitions/502.html)
- [CWE-611: Ακατάλληλος Περιορισμός Αναφοράς Εξωτερικής Οντότητας XML](https://cwe.mitre.org/data/definitions/611.html)
- [CWE-918: Server-Side Request Forgery](https://cwe.mitre.org/data/definitions/918.html)
- [CWE-22: Path Traversal](https://cwe.mitre.org/data/definitions/22.html)
- [CWE-73: Εξωτερικός Έλεγχος Ονόματος ή Διαδρομής Αρχείου](https://cwe.mitre.org/data/definitions/73.html)

### Εργαλεία και Πόροι

- CodeQL by GitHub
- OWASP WebGoat Project
- OWASP Top 10 2021
- Οδηγίες Ασφάλειας Java

### Αντιστοίχιση Συμμόρφωσης

| Ευπάθεια | PCI DSS | ISO 27001 | NIST |
|----------|---------|-----------|------|
| Μη Ασφαλής Αποσειριοποίηση | 6.5.8 | A.14.2.5 | SI-10 |
| XXE | 6.5.1 | A.14.2.5 | SI-10 |
| SSRF | 6.5.8 | A.13.1.3 | SC-7 |
| Path Traversal | 6.5.8 | A.14.2.5 | AC-3 |
