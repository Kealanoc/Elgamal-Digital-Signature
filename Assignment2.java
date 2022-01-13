import java.math.BigInteger;
import java.security.*;
import java.util.*;
import java.io.*;

// https://en.wikipedia.org/wiki/Modular_multiplicative_inverse
// https://en.wikipedia.org/wiki/Extended_Euclidean_algorithm

public class Assignment2 {
	public static void main(String[] args) throws UnsupportedEncodingException, NoSuchAlgorithmException{
		ElGamal e = new ElGamal();
		e.generateSignature();
		e.output();
		e.verify();
	}
}

class ElGamal {
	public String modulus = "b59dd79568817b4b9f6789822d22594f376e6a9abc0241846de426e5dd8f6eddef00b465f38f509b2b18351064704fe75f012fa346c5e2c442d7c99eac79b2bc8a202c98327b96816cb8042698ed3734643c4c05164e739cb72fba24f6156b6f47a7300ef778c378ea301e1141a6b25d48f1924268c62ee8dd3134745cdf7323";
	public String generator = "44ec9d52c8f9189e49cd7c70253c2eb3154dd4f08467a64a0267c9defe4119f2e373388cfa350a4e66e432d638ccdc58eb703e31d4c84e50398f9f91677e88641a2d2f6157e2f4ec538088dcf5940b053c622e53bab0b4e84b1465f5738f549664bd7430961d3e5a2e7bceb62418db747386a58ff267a9939833beefb7a6fd68";	

	// Convert hex string into BigInteger from base 16 (hexa)
	public BigInteger p = new BigInteger(modulus, 16);								
	public BigInteger g = new BigInteger(generator, 16);			
	// BigInteger that is p-1.	
	public BigInteger p_1 = p.subtract(BigInteger.ONE);

	// Read in file i.e. message before hashing
	public byte[] sig = signFile("Assignment2.class");

	// Generate the relevant numbers
	public BigInteger x = generateX();
	public BigInteger y = generateY();
	public BigInteger message = hash();
	public BigInteger k;
	public BigInteger r;
	public BigInteger s;

	public BigInteger generateX()
	{
		Random x = new Random();
		// BigInteger to create a random BigInteger between 0 and 2^n-1
		BigInteger rand = new BigInteger(p.bitLength(), x);
		while (rand.compareTo(p) == 1) {
			rand = new BigInteger(p.bitLength(), x);
		}
		return rand;					
	}
	// y = g^x (mod p)
	public BigInteger generateY()
	{	
		return g.modPow(x, p);					
	}

	// Generate r = g^k mod(p)
	public BigInteger generateR()
	{
		return g.modPow(k, p);
	}

	public BigInteger generateK()
	{
		Boolean isEqual = false;
		Random r = new Random();
		do {
			k = new BigInteger(p.bitLength(), 1, r);
			//Check if the gcd of the new K and p_1 is one
			isEqual = calculateGCD(p_1, k).equals(BigInteger.ONE);
		} 
		while(isEqual == false && k.compareTo(p_1) == 1);

		return k;					
	}

	// Generate S where S = (H(m)-xr)k^-1(mod p_1) where H is the hash function SHA-256.
	public BigInteger generateS()
	{
		// Get xr where x is private key
		BigInteger xr = x.multiply(r);
		// Get hashed message minus above value.
		BigInteger concatEucl = message.subtract(xr);
		// Get (h(m)-xr) and k's inverse
		BigInteger s = concatEucl.multiply(calculateInverse());
		return s.mod(p_1);
	}

	public BigInteger calculateGCD(BigInteger a, BigInteger b)
	{
		// Base case for recursion, 
		if(b.equals(BigInteger.ZERO)) return a;
		return calculateGCD(b, a.mod(b));
	}

	// Use SHA-256 to hash message (message is a file in this case.)
	public BigInteger hash()
	{
		try{
			// Get instance of digest
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			// Digest the message once into a byte array and convert it back as an biginteger to be returned
			byte[] m = md.digest(sig);
			return new BigInteger(m);
		}catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
	}

	public BigInteger[] extendEucl(BigInteger a, BigInteger b)
	{
		BigInteger[] i = new BigInteger[3];
		if(b.equals(BigInteger.ZERO)){
			i[0] = a;
			i[1] = BigInteger.ONE;
			i[2] = BigInteger.ZERO;
			return i;
		}

		i = extendEucl(b, a.mod(b));
		BigInteger x = i[1];
		BigInteger y = i[2];
		i[1] = y;
		i[2] = x.subtract((a.divide(b)).multiply(y));
		return i;
	}

	// Get multiplicative inverse of k using GCD.
	public BigInteger calculateInverse()
	{
		return extendEucl(k, p_1)[1].mod(p_1);
	}

	public byte[] signFile(String file) 
	{
		try{
			// Read in file
			File f = new File(file);
			FileInputStream inputFile = new FileInputStream(f);
			// Create a new byte array with the length of the message
			byte[] message = new byte[(int)f.length()];
			// Read file
			inputFile.read(message);
			inputFile.close();
			return message;
		} 
		catch(IOException e)
		{
			e.printStackTrace();
		} 
		return null;
	}

	public void generateSignature()
	{
		do 
		{
			k = generateK();
			r = generateR();
			s = generateS();
		} while(s.equals(BigInteger.ZERO));
	}

	// Check that the signature is correct
	public void verify()
	{
		Boolean rCheck = (r.compareTo(BigInteger.ZERO) == 1 && r.compareTo(p) == -1);
		Boolean sCheck = (s.compareTo(BigInteger.ZERO) == 1 && s.compareTo(p_1) == -1);
		System.out.println("0<r<p: " + rCheck + "\n0<s<p-1: " + sCheck);
		BigInteger left = g.modPow(message, p);
		BigInteger right = (y.modPow(r, p)).multiply(r.modPow(s,p)).mod(p);
		System.out.println("Verifying that  g^H(m) (mod p) = y^r r^s (mod p) is true: " + left.equals(right));
	}

	public void output()
	{
		try{
			PrintWriter pw1 = new PrintWriter(new FileWriter("K.txt"));
			PrintWriter pw2 = new PrintWriter(new FileWriter("R.txt"));
			PrintWriter pw3 = new PrintWriter(new FileWriter("S.txt"));
			pw1.println("K = " + k);
			pw1.close();
			pw2.println("R = " + r);
			pw2.println("R Hex = " + r.toString(16));
			pw2.close();
			pw3.println("S = " + s);
			pw3.println("S Hex = " + s.toString(16));
			pw3.close();
		}catch (IOException e) {
			e.printStackTrace();
		}
	}
}