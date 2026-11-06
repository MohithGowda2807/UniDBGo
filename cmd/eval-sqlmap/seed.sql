DROP TABLE IF EXISTS accounts;
DROP TABLE IF EXISTS api_keys;
CREATE TABLE accounts (id INT PRIMARY KEY, name VARCHAR(64) NOT NULL, email VARCHAR(128) NOT NULL);
CREATE TABLE api_keys (id INT PRIMARY KEY, account_id INT NOT NULL, secret VARCHAR(64) NOT NULL);
INSERT INTO accounts VALUES
 (1,'alice','alice@example.org'),(2,'bob','bob@example.org'),(3,'carol','carol@example.org'),(4,'dave','dave@example.org'),
 (5,'erin','erin@example.org'),(6,'frank','frank@example.org'),(7,'grace','grace@example.org'),(8,'heidi','heidi@example.org'),
 (9,'ivan','ivan@example.org'),(10,'judy','judy@example.org'),(11,'mallory','mallory@example.org'),(12,'niaj','niaj@example.org'),
 (13,'olivia','olivia@example.org'),(14,'peggy','peggy@example.org'),(15,'rupert','rupert@example.org'),(16,'sybil','sybil@example.org'),
 (17,'trent','trent@example.org'),(18,'victor','victor@example.org'),(19,'walter','walter@example.org'),(20,'zoe','zoe@example.org');
INSERT INTO api_keys VALUES (1,1,'sk_live_a1f3c9e2'),(2,2,'sk_live_b7d4e1f0'),(3,5,'sk_live_c2a8b6d3'),(4,11,'sk_live_d9e0f5a7'),(5,20,'sk_live_e4b1c3d8');
