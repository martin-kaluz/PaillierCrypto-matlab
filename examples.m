%% General BigInteger encryption/decryption

bit_length = 1024; % should be a value of 2^N
p = PaillierCrypto(bit_length); % create an instance of PaillierCrypto class

% generate public/private key pair
keys = p.generateKeys(); % assignment to variable is not required (keys are stored internally)
% keys = p.getKeys(); % to get the keys any time

% big integer definition
a = p.bi(123456); % equivalent of a = java.math.BigInteger('123456')
% a = p.bi('123456'); % alternative call
disp('original')
disp(a)

% encryption
ae = p.encrypt(a);
disp('encrypted')
disp(ae)

% decryption
ad = p.decrypt(ae);
disp('decrypted')
disp(ad)

%% Text encryption/decryption

bit_length = 1024; % should be a value of 2^N
p = PaillierCrypto(bit_length); % create an instance of PaillierCrypto class

% generate public/private key pair
keys = p.generateKeys(); % assignment to variable is not required (keys are stored internally)

% string definition
text = 'Hello Crypto World!';
disp('original text')
disp(text)

% encryption
text_encr = p.encryptString(text);
disp('encrypted text')
disp(text_encr)

% decryption
text_decr = p.decryptToString(text_encr);
disp('decrypted text')
disp(text_decr)

%% Homomorphic properties
bit_length = 1024; % should be a value of 2^N
p = PaillierCrypto(bit_length); % create an instance of PaillierCrypto class

% generate public/private key pair
keys = p.generateKeys(); % assignment to variable is not required (keys are stored internally)

% big integer definition
a = p.bi(1800);
b = p.bi(500);

% encrypt numbers
ae = p.encrypt(a);
be = p.encrypt(b);

% homomorphic addition (maps to aritmetic multiplication)
n2 = p.getPublicKey.n2;
ce = ae.multiply(be).mod(n2);

% decrypt result
c = p.decrypt(ce);
disp('1800 + 500 =')
disp(c)

% homomorphic multiplication
a = p.bi(20);
b = p.bi(55);
ae = p.encrypt(a);

ce = ae.modPow(b, n2);

% decrypt result
c = p.decrypt(ce);
disp('20 * 55 =')
disp(c)
