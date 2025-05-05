-- Create a dedicated MySQL user for secure imports
CREATE USER IF NOT EXISTS 'epssimport'@'%' IDENTIFIED BY 'strong_import_password';
GRANT SELECT, INSERT, UPDATE, DELETE ON epssdb.* TO 'epssimport'@'%';
FLUSH PRIVILEGES;
