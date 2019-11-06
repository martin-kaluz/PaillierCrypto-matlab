classdef PaillierCrypto < handle
    % PaillierCrypto: Constructs an object of PaillierCrypto class.
    %
    % my_paillier = PaillierCrypto() creates an object instance 'my_paillier'
    % that represents a toolbox for Paillier homomorphic crypto system. This class
    % includes methods for key generation, encryption, decryption, various utilities
    % and data-type conversion tools.
    %
    % Example:
    %
    %        my_paillier = PaillierCrypto();
    %        my_paillier = PaillierCrypto(BIT_LENGTH);
    %
    % PaillierCrypto class contains the following public methods:
    %
    %     Cryptography:
    %
    %        .generateKeys (see <a href="matlab:help PaillierCrypto.generateKeys">PaillierCrypto.generateKeys</a>)
    %        .encrypt (see <a href="matlab:help PaillierCrypto.encrypt">PaillierCrypto.encrypt</a>)
    %        .encryptString (see <a href="matlab:help PaillierCrypto.encryptString">PaillierCrypto.encryptString</a>)
    %        .decrypt (see <a href="matlab:help PaillierCrypto.decrypt">PaillierCrypto.decrypt</a>)
    %        .decryptToString (see <a href="matlab:help PaillierCrypto.decryptToString">PaillierCrypto.decryptToString</a>)
    %
    %     Utils:
    %
    %        .changeBitLength (see <a href="matlab:help PaillierCrypto.changeBitLength">PaillierCrypto.changeBitLength</a>)
    %        .getGenerator (see <a href="matlab:help PaillierCrypto.getGenerator">PaillierCrypto.getGenerator</a>)
    %        .getKeys (see <a href="matlab:help PaillierCrypto.getKeys">PaillierCrypto.getKeys</a>)
    %        .getPublicKey (see <a href="matlab:help PaillierCrypto.getPublicKey">PaillierCrypto.getPublicKey</a>)
    %        .getPrivateKey (see <a href="matlab:help PaillierCrypto.getPrivateKey">PaillierCrypto.getPrivateKey</a>)
    %        .getKeysStr (see <a href="matlab:help PaillierCrypto.getKeysStr">PaillierCrypto.getKeysStr</a>)
    %        .getPublicKeyStr (see <a href="matlab:help PaillierCrypto.getPublicKeyStr">PaillierCrypto.getPublicKeyStr</a>)
    %        .getPrivateKeyStr (see <a href="matlab:help PaillierCrypto.getPrivateKeyStr">PaillierCrypto.getPrivateKeyStr</a>)
    %        .setPublicKey (see <a href="matlab:help PaillierCrypto.setPublicKey">PaillierCrypto.setPublicKey</a>)
    %        .setPrivateKey (see <a href="matlab:help PaillierCrypto.setPrivateKey">PaillierCrypto.setPrivateKey</a>)
    %
    %     Random generators:
    %
    %        .randomBigIntPrimeLT (see <a href="matlab:help PaillierCrypto.randomBigIntPrimeLT">PaillierCrypto.randomBigIntPrimeLT</a>)
    %        .randomBigIntPrimeOfBitLength (see <a href="matlab:help PaillierCrypto.randomBigIntPrimeOfBitLength">PaillierCrypto.randomBigIntPrimeOfBitLength</a>)
    %        .randomBigIntOfBitLength (see <a href="matlab:help PaillierCrypto.randomBigIntOfBitLength">PaillierCrypto.randomBigIntOfBitLength</a>)
    %        .randomBigIntBetween (see <a href="matlab:help PaillierCrypto.randomBigIntBetween">PaillierCrypto.randomBigIntBetween</a>)
    %
    %     Conversion and math:
    %
    %        .bi (see <a href="matlab:help PaillierCrypto.bi">PaillierCrypto.bi</a>)
    %        .strToBi (see <a href="matlab:help PaillierCrypto.strToBi">PaillierCrypto.strToBi</a>)
    %        .biToStr (see <a href="matlab:help PaillierCrypto.biToStr">PaillierCrypto.biToStr</a>)
    %        .lcm (see <a href="matlab:help PaillierCrypto.lcm">PaillierCrypto.lcm</a>)
    %        .L (see <a href="matlab:help PaillierCrypto.L">PaillierCrypto.L</a>)
    %
    % Description of each method can be displayed using
    %
    %        help PaillierCrypto.[method name]
    %
    
    properties
        PublicKey
        BitLength = 1024 % default bit lenght
    end
    
    properties (Hidden)
        PrivateKey
        BigIntOne
        FlintShifter
        SafePowMargin = 100;
    end
    
    methods (Access = public)
        
        function obj = PaillierCrypto(varargin)
            if(nargin > 0)
                obj.BitLength = varargin{1};
                if(mod(log2(obj.BitLength),1)~=0)
                    warning(['BitLength parameter is not of 2^N. This may cause some trouble.' newline 'Suggested fix: [PaillierObject].changeBitLength(NEW_VALUE)']);
                end
            end
            obj.BigIntOne = obj.bi(1);
            obj.setFlintShifter();
        end
        
        function setFlintShifter(obj, fs)
            % experimental
            if(nargin>1)
                obj.FlintShifter = obj.bi(fs);
            else
                power = ceil(ceil(obj.BitLength/log2(10))/2)-1;
                max_power = floor(log2(realmax)/log2(10));
                if(power>max_power-obj.SafePowMargin)
                    power = max_power-obj.SafePowMargin;
                end
                obj.FlintShifter = obj.bi(10).pow(power);
            end
        end
        
        function fs = getFlintShifter(obj)
            % experimental
            fs = obj.FlintShifter;
        end
        
        function flint = doubleToFlint(obj, double_num)
            %experimental
            [n,d] = rat(double_num,1e-32);
            n_bi = obj.bi(n);
            d_bi = obj.bi(d);
            flint = obj.FlintShifter.multiply(n_bi).divide(d_bi);
        end
        
        function fout = multiplyEncrFlints(obj, fa, b)
            % TODO fix
            % experimental
            % multiplyEncrFlints(c, k), where c is ciphertext and k is number
            fout = fa.modPow(b, obj.PublicKey.n2);
        end
        
        function fout = addEncrFlints(obj, fa, fb)
            fout = fa.multiply(fb).mod(obj.PublicKey.n2);
        end
        
        function fout = subtractEncrFlints(obj, fa, fb)
            modInv = fb.modInverse(obj.PublicKey.n2);
            fout = fa.multiply(modInv);
        end
        
        function double_num = flintToDouble(obj,flint, varargin)
            if(nargin>2)
                precision = varargin{1};
            else
                precision = 100;
            end
            dr = flint.divideAndRemainder(obj.FlintShifter);
            d = dr(1).doubleValue;
            r = dr(2).divide(obj.FlintShifter.divide(obj.bi(10).pow(precision))).doubleValue()/(10^precision);
            double_num = d+r;
        end
        
        function changeBitLength(obj,len)
            % PaillierCrypto.changeBitLength(LENGTH) changes the bit LENGTH
            % of the crypto scheme.
            %
            % Usage:
            %       my_paillier.changeBitLength(1024);
            
            obj.BitLength = len;
        end
        
        function keys = generateKeys(obj, varargin)
            % PaillierCrypto.generateKeys() generates a set of public and private
            % keys using a bit length of PaillierCrypto.BitLength.
            % The method returns STRUCT of the following structure:
            %
            %     struct(
            %         publicKey:  struct(
            %             n:      [1×1 java.math.BigInteger],
            %             n2:     [1×1 java.math.BigInteger],
            %             g:      [1×1 java.math.BigInteger]
            %         )
            %         privateKey: struct(
            %             lambda: [1×1 java.math.BigInteger],
            %             mu:     [1×1 java.math.BigInteger],
            %             p:      [1×1 java.math.BigInteger],
            %             q:      [1×1 java.math.BigInteger],
            %             n:      [1×1 java.math.BigInteger],
            %             n2:     [1×1 java.math.BigInteger]
            %         )
            %    )
            %
            % Usage:
            %       keys = my_paillier.generateKeys();
            %
            % Optional:
            %       new_bit_length = 1024;
            %       keys = my_paillier.generateKeys(new_bit_length);
            
            if(nargin > 1)
                obj.changeBitLength(varargin{1});
            end
            while 1
                p = obj.randomBigIntPrimeOfBitLength(obj.BitLength/2);
                q = obj.randomBigIntPrimeOfBitLength(obj.BitLength/2);
                n = p.multiply(q);
                if(q.compareTo(p) ~= 0 && n.bitLength == obj.BitLength)
                    break;
                end
            end
            n2 = n.pow(2);
            g = obj.getGenerator(n, n2);
            lambda = obj.lcm(p.subtract(obj.BigIntOne), q.subtract(obj.BigIntOne));
            mu = obj.L(g.modPow(lambda, n2), n).modInverse(n);
            publicKey = struct(   ...
                'n',      n,      ...
                'n2',     n2,     ...
                'g',      g       ...
                );
            privateKey = struct(  ...
                'lambda', lambda, ...
                'mu'    , mu,     ...
                'p'     , p,      ...
                'q'     , q,       ...
                'n',      n,      ...
                'n2',     n2     ...
                );
            obj.PublicKey = publicKey;
            obj.PrivateKey = privateKey;
            keys = struct('publicKey', publicKey, 'privateKey', privateKey);
        end
        
        function decrypted = decryptDouble(obj, encrypted, varargin)
            %experimental
            % decryptDouble(obj, encrypted, min_expected, max_expected)
            if(nargin>2)
                min_expected = varargin{1};
                max_expected = varargin{2};
            else
                min_expected = -1e+50;
                max_expected = 1e+50;
            end
            flint = obj.decrypt(encrypted);
            decrypted = obj.flintToDouble(flint);
            if(decrypted<min_expected || decrypted>max_expected)
                flint = obj.toNRange(flint);
                decrypted = obj.flintToDouble(flint);
            end
        end
        
        function decrypted = decrypt(obj, encrypted)
            % PaillierCrypto.decrypt(ENCRYPTED) decrypts an ENCRYPTED of the type
            % java.math.BigInteger using a PaillierCrypto.PrivateKey.
            % The method returns java.math.BigInteger.
            %
            % Usage:
            %       decrypted = my_paillier.decrypt(encrypted);
            
            if(isempty(obj.PrivateKey)&&isempty(obj.PublicKey))
                warning(['First, generate public/private key pair.' newline 'see: <a href="matlab: help PaillierCrypto.generateKeys">PaillierCrypto.generateKeys()</a>.'])
                decrypted = -1;
                return
            end
            decrypted = encrypted ...
                .modPow(obj.PrivateKey.lambda,obj.PublicKey.n2) ...
                .subtract(obj.BigIntOne) ...
                .divide(obj.PublicKey.n) ...
                .multiply(obj.PrivateKey.mu) ...
                .mod(obj.PublicKey.n);
        end
        
        function  encrypted = encryptDouble(obj, double_num)
            %experimental
            flint = obj.doubleToFlint(double_num);
            if(double_num<0)
                encrypted = obj.encryptNegative(flint);
            else
                encrypted = obj.encrypt(flint);
            end
        end
        
        function in_n_range = toNRange(obj, bint)
            in_n_range = bint.add(obj.PublicKey.n.divide(obj.bi(2))).mod(obj.PublicKey.n).subtract(obj.PublicKey.n.divide(obj.bi(2)));
        end
        
        function encrypted = encryptNegative(obj, bint_neg)
            encrypted = obj.encrypt(bint_neg.mod(obj.PublicKey.n));
        end
        
        function encrypted = encrypt(obj, bint, varargin)
            % PaillierCrypto.encrypt(MESSAGE) encrypts a MESSAGE of the type
            % java.math.BigInteger using a PaillierCrypto.PublicKey.
            % The method returns java.math.BigInteger.
            %
            % Usage:
            %       encrypted = my_paillier.encrypt(message);
            
            if(isempty(obj.PrivateKey)&&isempty(obj.PublicKey))
                warning(['First, generate public/private key pair:' ...
                    newline 'see: <a href="matlab: help PaillierCrypto.generateKeys">PaillierCrypto.generateKeys()</a>.' ...
                    newline 'or define custom public key:' ...
                    newline 'see: <a href="matlab:help PaillierCrypto.setPublicKey">PaillierCrypto.setPublicKey</a>']);
                encrypted = -1;
                return
            end
            while 1
                r = obj.randomBigIntBetween(obj.bi(2),obj.PublicKey.n);
                if(nargin>2&&strcmpi(varargin{1},'strict'))
                    if(r.gcd(obj.PublicKey.n)==1)
                        break;
                    end
                else
                    break;
                end
            end
            encrypted = obj.PublicKey.g ...
                .modPow(bint,obj.PublicKey.n2) ...
                .multiply( ...
                r.modPow(obj.PublicKey.n,obj.PublicKey.n2) ...
                ).mod(obj.PublicKey.n2);
            
        end
        
        function encrypted = encryptString(obj, str)
            % PaillierCrypto.encryptString(MESSAGE) encrypts a MESSAGE
            % of the type String using a PaillierCrypto.PublicKey.
            % The method returns java.math.BigInteger.
            %
            % Usage:
            %       encrypted = my_paillier.encryptString(message);
            
            bint = obj.strToBi(str);
            encrypted = obj.encrypt(bint);
        end
        
        function decrypted = decryptToString(obj, encrypted)
            % PaillierCrypto.decryptToString(ENCRYPTED) decrypts an ENCRYPTED of
            % the type java.math.BigInteger using a PaillierCrypto.PrivateKey.
            % The method returns String.
            %
            % Usage:
            %       message = my_paillier.decryptToString(encrypted);
            
            bint = obj.decrypt(encrypted);
            decrypted = obj.biToStr(bint);
        end
        
        function r = randomBigIntPrimeLT(obj, opt)
            % PaillierCrypto.randomBigIntPrimeLT(LOWERTHAN) generates a prime P
            % of the type java.math.BigInteger, such that P < LOWERTHAN.
            % LOWERTHAN can be either of type java.math.BigInteger, String, or Double.
            %
            % Usage:
            %       random_prime_lt = my_paillier.randomBigIntPrimeLT(upper_limit);
            
            if(strcmpi(class(opt),'java.math.BigInteger'))
                bit_size = opt.bitLength;
            elseif(ischar(opt))
                opt = obj.bi(opt);
                bit_size = opt.bitLength;
            else
                opt = obj.bi(num2str(opt));
                bit_size = opt.bitLength;
            end
            while 1
                r = obj.randomBigIntOfBitLength(bit_size);
                if (r.isProbablePrime(1) && r.compareTo(opt)<1)
                    break;
                end
            end
        end
        
        function r = randomBigIntPrimeOfBitLength(obj, length)
            % PaillierCrypto.randomBigIntPrimeOfBitLength(LENGTH) generates a prime P
            % of the type java.math.BigInteger, such that P.bitLength is LENGTH.
            %
            % Usage:
            %       random_prime = my_paillier.randomBigIntPrimeOfBitLength(num_of_bits);
            
            while 1
                r = obj.randomBigIntOfBitLength(length);
                if (r.isProbablePrime(1))
                    break;
                end
            end
        end
        
        function bint = randomBigIntOfBitLength(obj, bit_size)
            % PaillierCrypto.randomBigIntOfBitLength(LENGTH) generates
            % a random number N of the type java.math.BigInteger,
            % such that N.bitLength is LENGTH.
            %
            % Usage:
            %       random = my_paillier.randomBigIntOfBitLength(num_of_bits);
            
            javaRandom = java.util.Random();
            bint = obj.bi(bit_size, javaRandom);
        end
        
        function r = randomBigIntBetween(obj, lower, upper)
            % PaillierCrypto.randomBigIntBetween(LOWER, UPPER) generates
            % a random number N of the type java.math.BigInteger,
            % such that LOWER <= N <= UPPER.
            % Both LOWER and UPPER are of the type java.math.BigInteger.
            %
            % Usage:
            %       random_Between = my_paillier.randomBigIntBetween(lower, upper);
            
            bit_size = upper.bitLength;
            while 1
                r = obj.randomBigIntOfBitLength(bit_size);
                if (r.compareTo(lower)>=0 && r.compareTo(upper)<=0)
                    break;
                end
            end
        end
        
        function out = getGenerator(obj, n, n2)
            % PaillierCrypto.getGenerator(N, N2) returns a generator
            % number G of the type java.math.BigInteger.
            % This method is used for public/private key generation.
            % Both N and N2 = N.pow(2) are of the type java.math.BigInteger.
            %
            % Usage:
            %       g = my_paillier.getGenerator(n, n2);
            
            alpha = obj.randomBigIntBetween(obj.bi(2),n);
            beta = obj.randomBigIntBetween(obj.bi(2),n);
            out = alpha ...
                .multiply(n) ...
                .add(obj.bi(1)) ...
                .multiply(beta.modPow(n, n2)) ...
                .mod(n2);
        end
        
        function out = L(obj, in1, in2)
            % utility method used in Paillier crypto system
            out = in1.subtract(obj.BigIntOne).divide(in2);
        end
        
        function keys = getKeys(obj)
            % PaillierCrypto.getKeys() returns a pair of public/private
            % keys stored in PaillierCrypto object. Keys are of the type
            % java.math.BigInteger.
            %
            % Usage:
            %       keys = my_paillier.getKeys();
            
            keys = struct('publicKey', obj.PublicKey, 'privateKey', obj.PrivateKey);
        end
        
        function key = getPublicKey(obj)
            % PaillierCrypto.getPublicKey() returns a public
            % key stored in PaillierCrypto object. Keys are of the type
            % java.math.BigInteger.
            %
            % Usage:
            %       public_key = my_paillier.getPublicKey();
            
            key = obj.PublicKey;
        end
        
        function key = getPrivateKey(obj)
            % PaillierCrypto.getPrivateKey() returns a private
            % key stored in PaillierCrypto object. Keys are of the type
            % java.math.BigInteger.
            %
            % Usage:
            %       private_key = my_paillier.getPrivateKey();
            
            key = obj.PrivateKey;
        end
        
        function keys = getKeysStr(obj)
            % PaillierCrypto.getKeysStr() returns a pair of public/private
            % keys stored in PaillierCrypto object. Keys are of the type
            % String.
            %
            % Usage:
            %       keys = my_paillier.getKeysStr();
            
            publicKey = struct;
            privateKey = struct;
            fnames = fieldnames(obj.PublicKey);
            for i = 1:length(fnames)
                publicKey.(fnames{i}) = string(obj.PublicKey.(fnames{i}).toString());
            end
            fnames = fieldnames(obj.PrivateKey);
            for i = 1:length(fnames)
                privateKey.(fnames{i}) = string(obj.PrivateKey.(fnames{i}).toString());
            end
            keys = struct('publicKey', publicKey, 'privateKey', privateKey);
        end
        
        function key = getPublicKeyStr(obj)
            % PaillierCrypto.getPublicKeyStr() returns a public
            % key stored in PaillierCrypto object. Keys are of the type
            % String.
            %
            % Usage:
            %       public_key = my_paillier.getPublicKeyStr();
            
            key = struct;
            fnames = fieldnames(obj.PublicKey);
            for i = 1:length(fnames)
                key.(fnames{i}) = string(obj.PublicKey.(fnames{i}).toString());
            end
        end
        
        function key = getPrivateKeyStr(obj)
            % PaillierCrypto.getPrivateKeyStr() returns a private
            % key stored in PaillierCrypto object. Keys are of the type
            % String.
            %
            % Usage:
            %       private_key = my_paillier.getPrivateKeyStr();
            
            key = struct;
            fnames = fieldnames(obj.PrivateKey);
            for i = 1:length(fnames)
                key.(fnames{i}) = string(obj.PrivateKey.(fnames{i}).toString());
            end
        end
        
        function setPublicKey(obj, n, g)
            % PaillierCrypto.setPublicKey(N, G) initializes
            % PaillierCrypto.PublicKey property.
            % N and G are components of Paillier public key and
            % are of the type java.math.BigInteger.
            %
            % Usage:
            %       my_paillier.setPublicKey(n, g);
            
            obj.PublicKey.n = n;
            obj.PublicKey.n2 = n.pow(2);
            obj.PublicKey.g = g;
        end
        
        function setPrivateKey(obj, lambda, mu)
            % PaillierCrypto.setPrivateKey(LAMBDA, MU) initializes
            % PaillierCrypto.PrivateKey property.
            % LAMBDA and MU are components of Paillier private key and
            % are of the type java.math.BigInteger.
            %
            % Usage:
            %       my_paillier.setPrivateKey(lambda, mu);
            
            obj.PrivateKey.lambda = lambda;
            obj.PrivateKey.mu = mu;
        end
        
    end
    
    
    methods (Static)
        
        function out = bi(in, varargin)
            % PaillierCrypto.bi(INT) returns a big integer B of the type
            % java.math.BigInteger and numerical value of INT.
            % INT can be either of type Double or String.
            %
            % Usage:
            %       big_int1 = my_paillier.bi(123456);
            %       big_int2 = my_paillier.bi('123456');
            
            if(~ischar(in)&&nargin==1)
                in = num2str(in);
            end
            if(nargin > 1)
                out = java.math.BigInteger(in, varargin{1});
            else
                out = java.math.BigInteger(in);
            end
        end
        
        function bint = strToBi(str)
            % PaillierCrypto.strToBi(TEXT) returns a big integer B of the type
            % java.math.BigInteger that numerically represent a binary form
            % of TEXT's ASCII characters in UTF-8 encoding. This method is
            % be used to prepare text strings for Paillier encryption.
            %
            % Usage:
            %       text_bint = my_paillier.strToBi('Hello World!');
            
            message_bin_char = dec2bin(str,8);
            message_uint8_arr = uint8(bin2dec(message_bin_char));
            bint = java.math.BigInteger(message_uint8_arr);
        end
        
        function str = biToStr(bint)
            % PaillierCrypto.biToStr(BINT) returns a text string that was decoded
            % from the big integer representation BINT of the type
            % java.math.BigInteger using UTF-8 encoding. This method is
            % be used to decode text messages from Paillier decrypted big integers.
            %
            % Usage:
            %       text = my_paillier.biToStr(bint);
            
            str = char(bint.toByteArray');
        end
        
        
        function out = lcm(in1, in2)
            % PaillierCrypto.lcm(A, B) finds lowest common multiple of
            % A and B of the type java.math.BigInteger.
            % The method returns java.math.BigInteger.
            
            out = in1.divide(in1.gcd(in2)).multiply(in2);
        end
        
    end
end

