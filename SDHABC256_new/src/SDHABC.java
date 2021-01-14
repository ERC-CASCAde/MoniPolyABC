
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.milagro.amcl.BLS48.*;
import org.apache.milagro.amcl.RAND;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author nsyt1
 */
public class SDHABC {   
    /*
    public SDHABC(){
        //y^2=x^3-7, found g=(2,1)
        BigInteger r = toBigInteger(new BIG(ROM.CURVE_Order));
        BigInteger p = toBigInteger(new BIG(ROM.Modulus));
        
        for(int i=-5;i<5;i++){        
        BigInteger x = BigInteger.valueOf(i);        
        System.out.println("x: "+x);
        
        x=x.modPow(BigInteger.valueOf(3), p);
        BigInteger y = x.add(BigInteger.valueOf(-7)).mod(p);
        y = y.modPow(BigInteger.valueOf(2).modInverse(r), p);
        System.out.println("y: "+y);        

        y=y.modPow(BigInteger.valueOf(2), p);        
        y = y.subtract(BigInteger.valueOf(-7));
        
        x = y.modPow(BigInteger.valueOf(3).modInverse(r), p);
        System.out.println("check: "+ x);        
        }
        System.out.println("r: "+r);
        System.out.println("bits: "+r.bitLength());
        System.out.println("p: "+p);        
        System.out.println("bits: "+p.bitLength());
        System.out.println(new BigInteger("7DE40020",16).bitLength());
        
        
    }
    */
    /*
    public SDHABC(){
        //gen parameter u for BLS48
        //35 bits ,g=(2,1)
        //u: +2^3+2^6+2^25+2^35 = 802000048
        //Curve is y^2=x^3+4 (or) 5 -3 -7 -18 
        //p= 15B62274096F5CA43A83FB647D339F71B5FDE7506D117B83A7F2DFA895C8789656CD8AF3679770A6AE9931D982D29565ACC6A23AF21B364DDB26663FA58EA76A991BDB5950510AD56AF74B65AAB183 (629 bits) M-Type 
        //
        //u: -2^7-2^10-2^20+2^34-2^35 = -400100480
        //Curve is y^2=x^3+4 (or) 20 -3 -15 -18 -21 
        //p= 556D5F478F8956BFB608A85CDB8A7D73553F2FC98B23950D55807E1047A6D40E473633ABECFDA43D2FCE76FDA05E375FA1BFB62BCC0AC2ACF4F43DE5D49F34ECEF613758FEA800C543001692B (611 bits) M-Type
        //
        //36 bits 
        //u: -2^6-2^15+2^19-2^36 = -FFFF88040
        //Curve is y^2=x^3+6 (or) 16 -2 -11 -13 -14 -18 -20 
        //p= 5552857893E46D52646955E2A21F5B024D81D2128F5543C3F32C871015A521C4C944AFEAB9CB474B97BCC3E38B50938CBF99E4A7C4A406F597D2C8C9D54A3B76438545960F945F2347F4DA580D696D2FEB (647 bits) D-Type
        //
        //u: -2^10+2^26-2^32-2^36 = -10FC000400
        //Curve is y^2=x^3+5 (or) 9 16 -2 -12 -21 
        //p= F9F2F1514FBC1C2BC341936AAA7183160DC814480D8DF6B7471750E68680A2B2CAAA824B890F889B529F7AAC5D4D460631C994C1CFBDFF1EC4FE805A98D7FBA5A921C60CA7FD5500602805829A56AFFEAB (648 bits) D-Type

        BigInteger u,r,p;
        BigInteger _2 = BigInteger.valueOf(2);
        int i=0,bitone=0;
        do{
            do{
                u = new BigInteger(36,new SecureRandom());
            }while(u.bitCount()>14 | u.bitLength()<35 |
                  !u.mod(BigInteger.valueOf(24)).mod(BigInteger.valueOf(3)).equals(BigInteger.ONE) |
                  (!u.mod(BigInteger.valueOf(24)).mod(BigInteger.valueOf(8)).equals(BigInteger.ZERO) && 
                  !u.mod(BigInteger.valueOf(24)).mod(BigInteger.valueOf(8)).equals(BigInteger.valueOf(7))));
            //u = _2.pow(7).subtract(BigInteger.ONE).subtract(_2.pow(10)).subtract(_2.pow(30)).subtract(_2.pow(32));
            //u = new BigInteger("7DE40020",16);
            u=new BigInteger("802000048",16);
            r = u.pow(16).subtract(u.pow(8)).add(BigInteger.ONE);
            p = u.subtract(BigInteger.ONE).pow(2).divide(BigInteger.valueOf(3)).multiply(r).add(u);
            i++;
            System.out.println(i);
        }while(!p.mod(BigInteger.valueOf(8)).equals(BigInteger.valueOf(3)) | !r.isProbablePrime(16) | !p.isProbablePrime(16)); 
        
        System.out.println("|GT points|/r is prime? "+p.pow(16).subtract(p.pow(8)).add(BigInteger.ONE).divide(r).isProbablePrime(16));
        System.out.println(u.toString(16));        
        System.out.println(u.bitCount());
        System.out.println(u.bitLength());
        System.out.println("u prime? " + u.isProbablePrime(16));        
        System.out.println("u-1 prime? " + u.subtract(BigInteger.ONE).isProbablePrime(16));        
        System.out.println("r prime? " + r.isProbablePrime(16));        
        System.out.println(r.toString(16));
        System.out.println(r.toString());
        System.out.println(r.bitLength());
        System.out.println("p prime? " + p.isProbablePrime(16));
        System.out.println(p.toString(16));   
        System.out.println(p.toString());
        System.out.println(p.bitLength());
        System.out.println(p.bitLength()/8);
        System.out.println("p mod 8 = "+p.mod(BigInteger.valueOf(8)));
    }
    */
    public ABCparam Setup(int attrSize){
        RAND RNG = new RAND();
        ECP[] a=new ECP[attrSize];
        ECP8[] X=new ECP8[attrSize];
        ECP a0 = ECP.generator();
        ECP8 g2 = ECP8.generator();        
        
        BIG q=new BIG(ROM.CURVE_Order);
	
        SecureRandom rand = new SecureRandom();
        RNG.clean();
	RNG.seed(100,rand.generateSeed(100));        
        
        BIG x=BIG.randomnum(q,RNG);
        ECP8 g2x = PAIR256.G2mul(g2, x);
        
        BIG xprime=BIG.randomnum(q,RNG);
        BIG _1 = new BIG();
        _1.one();
        
        BIG j = new BIG();        
        j.zero();
        
        for(int i=0;i<attrSize;i++){            
            a[i] = PAIR256.G1mul(a0, xprime.powmod(j, q));
            X[i] = PAIR256.G2mul(g2, xprime.powmod(j, q));
            j.add(_1);
        }
        
        ECP b = PAIR256.G1mul(a0,BIG.randomnum(q,RNG));
        ECP c = PAIR256.G1mul(a0,BIG.randomnum(q,RNG));
        ABCpk pk = new ABCpk(a0,b,c,a,g2,g2x,X);
        ABCsk sk = new ABCsk(x,xprime);
	//s.toBytes(S);
	//G.toBytes(W);
        
        /*//simple operation benchmark
        long start, total1=0, total2=0, total3=0, total4=0, totalrsa=0;       
        FP48 pair = PAIR256.fexp(PAIR256.ate(g2,a0));
         
        //for RSA
        BigInteger qq,Q,pp,P,N,R;
        do{
                qq = new BigInteger(15360/2-1, 16, rand);
                pp = new BigInteger(15360/2-1, 16, rand);
                Q=qq.multiply(BigInteger.valueOf(2)).add(BigInteger.ONE);
                P=pp.multiply(BigInteger.valueOf(2)).add(BigInteger.ONE);
                N = P.multiply(Q);
        }while(!qq.isProbablePrime(16) || !pp.isProbablePrime(16) || !Q.isProbablePrime(16) || !P.isProbablePrime(16) || N.bitLength()<15359);
        R=new BigInteger(rand.generateSeed(15360/8)).mod(N);
        //end RSA
         
        for(int i=0;i<100;i++){
            BIG num = BIG.randomnum(q,RNG); 
            BigInteger num1 = toBigInteger(num);
             
            start = System.nanoTime();
            a0=PAIR256.G1mul(a0, num);
            total1 += System.nanoTime() - start;
             
            start = System.nanoTime();
            PAIR256.G2mul(g2, num);
            total2 += System.nanoTime() - start;
             
            start = System.nanoTime();
            pair.pow(num);
            total3 += System.nanoTime() - start;           
             
            start = System.nanoTime();
            PAIR256.fexp(PAIR256.ate(g2,a0));
            total4 += System.nanoTime() - start;
             
            start = System.nanoTime();
            R.modPow(num1, N);
            totalrsa += System.nanoTime() - start;
        }
        System.out.println("G1 scalar multiplication takes  : "+java.util.concurrent.TimeUnit.MILLISECONDS.convert(total1/100, java.util.concurrent.TimeUnit.NANOSECONDS)+"ms");
        System.out.println("G2 scalar multiplication takes  : "+java.util.concurrent.TimeUnit.MILLISECONDS.convert(total2/100, java.util.concurrent.TimeUnit.NANOSECONDS)+"ms");
        System.out.println("GT exponentiation takes         : "+java.util.concurrent.TimeUnit.MILLISECONDS.convert(total3/100, java.util.concurrent.TimeUnit.NANOSECONDS)+"ms");
        System.out.println("Pairing takes                   : "+java.util.concurrent.TimeUnit.MILLISECONDS.convert(total4/100, java.util.concurrent.TimeUnit.NANOSECONDS)+"ms");
        System.out.println("RSA modular exponentiation takes: "+java.util.concurrent.TimeUnit.MILLISECONDS.convert(totalrsa/100, java.util.concurrent.TimeUnit.NANOSECONDS)+"ms");
        //end*/
        
        return new ABCparam(pk, sk);
    }
    
    public ABCcred Issuing(ABCpk pk, String[] A, ABCsk sk) throws Exception{
        
        if(A.length>pk.get_a().length-1){
            throw new Exception("Maximum supported attribute size is "+(pk.get_a().length-1)+" only.");
        }
        
        RAND RNG = new RAND();
        BIG[] attr = new BIG[A.length];
        BIG[] alphas = new BIG[A.length+1];
        BIG order = new BIG(ROM.CURVE_Order);
        
        try {
            SecureRandom rand = new SecureRandom();
            RNG.clean();
            RNG.seed(100,rand.generateSeed(100));
        
            MessageDigest H = MessageDigest.getInstance("SHA-512");
                        
            for(int i=0;i<attr.length;i++){                
                byte[] temp = H.digest(A[i].getBytes());
                byte[] hash = new byte[80];
                for(int j=0;j<hash.length;j++){
                    if(j<temp.length)
                        hash[j]=temp[j];
                    else
                        hash[j]=0x00;
                }
                attr[i]= BIG.fromBytes(hash);
                attr[i].mod(order);
            }
            alphas = convertToAlphas(attr, order);
            
            //user chooses random tilde{s,alpha_0,...\alpha_n}
            BIG s1 = BIG.randomnum(order,RNG);
            BIG tildeS = BIG.randomnum(order,RNG);
            BIG[] tildeA = new BIG[alphas.length];
            
            //calculate C,R
            ECP C = PAIR256.G1mul(pk.get_b(), s1);
            ECP R = PAIR256.G1mul(pk.get_b(), tildeS);
            
            for(int i=0;i<tildeA.length;i++){
                C.add(PAIR256.G1mul(pk.get_a()[i], alphas[i]));
                
                tildeA[i] = BIG.randomnum(order,RNG);
                R.add(PAIR256.G1mul(pk.get_a()[i], tildeA[i]));
            }
            //send C,R to issuer
            
            //issuer gives challenge
            BIG e = BIG.randomnum(order,RNG);
            
            //send response to issuer
            tildeS.add(BIG.modmul(e, s1, order));
            tildeS.mod(order);
            for(int i=0;i<tildeA.length;i++){
                tildeA[i].add(BIG.modmul(e, alphas[i], order));
                tildeA[i].mod(order);
            }
            
            //issuer verify
            ECP _C = PAIR256.G1mul(pk.get_b(), tildeS);
            for(int i=0;i<tildeA.length;i++){
                _C.add(PAIR256.G1mul(pk.get_a()[i], tildeA[i]));
            }
            R.add(PAIR256.G1mul(C, e));
            
            if(_C.equals(R)){
           
                BIG t = BIG.randomnum(order,RNG);
                BIG s2 = BIG.randomnum(order,RNG);
                C.add(PAIR256.G1mul(pk.get_b(), s2));
                C.add(pk.get_c());
                BIG _t = new BIG(t);
                //_t.copy(t);
                _t.add(sk.get_x());
                _t.invmodp(order);
                ECP v = PAIR256.G1mul(C,_t);
                
                //received credential (t,s2,v)
                s1.add(s2);     
                s1.mod(order);
                
                //verify if this is a valid credential
                ECP temp = PAIR256.G1mul(v,t);
                temp.neg();
                
                temp.add(pk.get_c());
                temp.add(PAIR256.G1mul(pk.get_b(),s1));
                
                for(int i=0;i<alphas.length;i++){
                    temp.add(PAIR256.G1mul(pk.get_a()[i],alphas[i]));
                }
                
                FP48 left=PAIR256.fexp(PAIR256.ate(pk.get_g2x(),v));
                
                FP48 right=PAIR256.fexp(PAIR256.ate(pk.get_g2(),temp));
                
                
		if (left.equals(right)){
                    return new ABCcred(t,s1,v,A,alphas);
                }
                else{
                    return null;
                }
            }
            else{
                return null;
            }
        
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(SDHABC.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
    
    public boolean proofOfPossession(ABCpk pk, ABCcred cred){
        try{
        MessageDigest H = MessageDigest.getInstance("SHA-512");
        RAND RNG = new RAND();
        BIG r,y,_r,_y,_ty,_s,_o0,_o1;
        //BIG[] _alpha = new BIG[cred.get_alphas().length];        
        BIG order = new BIG(ROM.CURVE_Order);
        
        SecureRandom rand = new SecureRandom();
        RNG.clean();
	RNG.seed(100,rand.generateSeed(100));
        
        //prover sends commitment and witnesses        
        r = BIG.randomnum(order,RNG);
        y = BIG.randomnum(order,RNG);
        BIG yinv=new BIG(y);
        //yinv.copy(y);
        yinv.invmodp(order);
        _r = BIG.randomnum(order,RNG);
        _y = BIG.randomnum(order,RNG);
        _ty = BIG.randomnum(order,RNG);
        _s = BIG.randomnum(order,RNG);
        _o0 = BIG.randomnum(order,RNG);
        _o1 = BIG.randomnum(order,RNG);
        
        ECP V1 = PAIR256.G1mul(cred.get_v(), BIG.modmul(BIG.modmul(r, r, order), yinv, order));
        ECP V2 = PAIR256.G1mul(V1, _y);
        ECP Y1 = PAIR256.G1mul(V1, _ty);
        ECP8 Y2 = PAIR256.G2mul(pk.get_X()[0], _o0);        
        Y2.add(PAIR256.G2mul(pk.get_X()[1], _o1));
        Y1.add(PAIR256.G1mul(pk.get_c(), _r));
        Y1.add(PAIR256.G1mul(pk.get_b(), _s));
        
        //for(int i=0;i<_alpha.length;i++){
        //    _alpha[i] = BIG.randomnum(order,RNG);
        //    Y.add(PAIR.G1mul(pk.get_a()[i], _alpha[i]));
        //}
        BIG[] w = new BIG[cred.get_A().length-1];
        for(int i=0;i<w.length;i++){
             byte[] temp = H.digest(cred.get_A()[i].getBytes());
                byte[] hash = new byte[80];
                for(int j=0;j<hash.length;j++){
                    if(j<temp.length)
                        hash[j]=temp[j];
                    else
                        hash[j]=0x00;
                }
            w[i] = BIG.fromBytes(hash);
            w[i].mod(order);
        }
        w = convertToAlphas(w,order);        
        
        //ECP M = PAIR.G1mul(pk.get_a0(), cred.get_alphas()[0]);
        ECP W = PAIR256.G1mul(pk.get_a0(), w[0]);
        for(int i=1;i<w.length;i++){            
            W.add(PAIR256.G1mul(pk.get_a()[i], w[i]));
        }
        W = PAIR256.G1mul(W, r);
        
        //verifier replies a challenge
        BIG e = BIG.randomnum(order,RNG);
        
        //prover sends response
        _r.add(BIG.modmul(e, BIG.modmul(r, r, order), order)); 
        _r.mod(order);
        _y.add(BIG.modmul(e, y, order));        
        _y.mod(order);
        _ty.sub(BIG.modmul(e, BIG.modmul(cred.get_t(), y, order), order));        
        _ty.mod(order);
        _s.add(BIG.modmul(e, BIG.modmul(cred.get_s(),BIG.modmul(r, r, order),order), order));
        _s.mod(order);
        _o1.add(BIG.modmul(e, r, order)); 
        _o1.mod(order);
        
        byte[] temph = H.digest(cred.get_A()[cred.get_A().length-1].getBytes());
        byte[] hash = new byte[80];
        for(int j=0;j<hash.length;j++){
            if(j<temph.length)
                hash[j]=temph[j];
            else
                hash[j]=0x00;
        }
        
        r = BIG.modmul(r, BIG.fromBytes(hash), order);
        _o0.add(BIG.modmul(e, r, order)); 
        _o0.mod(order);        
        //for(int i=0;i<_alpha.length;i++){
        //    _alpha[i].add(BIG.modmul(e, BIG.modmul(cred.get_alphas()[i],r,order), order));
        //    _alpha[i].mod(order);
        //}
        
        //verifier checks
        FP48[] ll=PAIR256.initmp();
        ECP8 temp2 = PAIR256.G2mul(pk.get_X()[0],_o0);
        temp2.add(PAIR256.G2mul(pk.get_X()[1],_o1));
        temp2.sub(Y2);
        PAIR256.another(ll, temp2, W);
        
        ECP temp = PAIR256.G1mul(V1, _ty);
        temp.add(PAIR256.G1mul(pk.get_c(), _r));
        temp.add(PAIR256.G1mul(pk.get_b(), _s));
        //for(int i=0;i<_alpha.length;i++){
        //    temp.add(PAIR.G1mul(pk.get_a()[i], _alpha[i]));            
        //}
        temp.sub(Y1);
        //temp.add(PAIR.G1mul(W, e));
        PAIR256.another(ll, pk.get_g2(), temp);
        //FP12 left2 = PAIR.fexp(PAIR.ate(pk.get_g2(), temp));
        
        //FP12 right1 = PAIR.fexp(PAIR.ate(pk.get_g2(), Y));
        
        temp = PAIR256.G1mul(V1, _y);
        temp.sub(V2);
        
        //FP12 right2 = PAIR.fexp(PAIR.ate(pk.get_g2x(), temp2));
        
        //right1.mul(right2);
        
        //FP12[] rr=PAIR.initmp();
	//PAIR.another(rr,pk.get_g2(), Y);
	
	FP48 right=PAIR256.fexp(PAIR256.ate(pk.get_g2x(), temp));
        
        if(PAIR256.fexp(PAIR256.miller(ll)).equals(right))            
            return true;
        else
            return false;
        }
        catch(Exception e){
            Logger.getLogger(SDHABC.class.getName()).log(Level.SEVERE, null, e);
        }
        
        return false;
    }    
    
    public boolean proofOfAND(ABCpk pk, ABCcred cred, String[] Aprime) throws Exception{
        try{
        MessageDigest H = MessageDigest.getInstance("SHA-512");
        RAND RNG = new RAND();
        BIG r,y,_r,_y,_ty,_s;        
        BIG order = new BIG(ROM.CURVE_Order);
        
        BIG[] m;
        
        //new intersection function        
        //if threshold doesn't met, exception thrown
        //so, we don't need to perform a check anymore
        ArrayList<String>[] result = findSame(Aprime.length,cred.get_A(),Aprime);                
        
        if(Aprime.length<cred.get_A().length){
            m = new BIG[result[0].size()];
            for(int i=0;i<m.length;i++){
                 byte[] temp = H.digest(result[0].get(i).getBytes());
                byte[] hash = new byte[80];
                for(int j=0;j<hash.length;j++){
                    if(j<temp.length)
                        hash[j]=temp[j];
                    else
                        hash[j]=0x00;
                }
                m[i] = BIG.fromBytes(hash);
                m[i].mod(order);
            }
            //encode them
            m = syntheticDivision(cred.get_alphas(),convertToAlphas(m, order))[0];
        }
        else{
            m = new BIG[1];
            m[0] = new BIG();
            m[0].one();
        }
        
        
        SecureRandom rand = new SecureRandom();
        RNG.clean();
	RNG.seed(100,rand.generateSeed(100));
        
        //BIG[] _beta = new BIG[beta.length];
        
        r = BIG.randomnum(order,RNG);
        y = BIG.randomnum(order,RNG);
        BIG yinv=new BIG(y);
        yinv.invmodp(order);
        _r = BIG.randomnum(order,RNG);
        _y = BIG.randomnum(order,RNG);
        _ty = BIG.randomnum(order,RNG);
        _s = BIG.randomnum(order,RNG);
        
        ECP Vprime = PAIR256.G1mul(cred.get_v(), BIG.modmul(r, yinv, order));
        ECP V = PAIR256.G1mul(Vprime, _y);
        
        ECP M = PAIR256.G1mul(pk.get_a0(), m[0]);
        for(int i=1;i<m.length;i++){
            M.add(PAIR256.G1mul(pk.get_a()[i], m[i]));
        }
        M = PAIR256.G1mul(M, r);
        
        ECP Y = PAIR256.G1mul(Vprime, _ty);
        Y.add(PAIR256.G1mul(pk.get_c(), _r));
        Y.add(PAIR256.G1mul(pk.get_b(), _s));        
        
        //verifier replies a challenge
        BIG e = BIG.randomnum(order,RNG);        
      
        //prover sends response
        //\hat{r}=\tilde{r}+er
        _r.add(BIG.modmul(e, r, order));
        _r.mod(order);        
        //\hat{y}=\tilde{y}+ey
        _y.add(BIG.modmul(e, y, order));        
        _y.mod(order);
        //\hat{t_y}=\tilde{t_y}-ety
        _ty.sub(BIG.modmul(e, BIG.modmul(cred.get_t(), y, order), order));  
        _ty.mod(order);
        //\hat{s}=\tilde{s}+esr
        _s.add(BIG.modmul(e, BIG.modmul(cred.get_s(),r,order), order));
        _s.mod(order);
                
        //verifier checks        
        //new checking, only 3 pairings
        FP48[] ll=PAIR256.initmp();	
        
        BIG[] z = new BIG[Aprime.length];
        for(int i=0;i<Aprime.length;i++){
            byte[] temp = H.digest(Aprime[i].getBytes());
            byte[] hash = new byte[80];
                for(int j=0;j<hash.length;j++){
                    if(j<temp.length)
                        hash[j]=temp[j];
                    else
                        hash[j]=0x00;
                }
            z[i] = BIG.fromBytes(hash);
            z[i].mod(order);
        }
        z = convertToAlphas(z, order);
        
        ECP8 temp2 = PAIR256.G2mul(pk.get_g2(), z[0]);
        for(int i=1;i<z.length;i++){
            temp2.add(PAIR256.G2mul(pk.get_X()[i], z[i]));            
        }
        PAIR256.another(ll,temp2, PAIR256.G1mul(M, e));
        
        
        ECP temp=PAIR256.G1mul(pk.get_b(), _s);
        temp.add(PAIR256.G1mul(pk.get_c(), _r));
        temp.add(PAIR256.G1mul(Vprime, _ty));        
        temp.sub(Y);
        
	PAIR256.another(ll,pk.get_g2(), temp);
	FP48 left=PAIR256.fexp(PAIR256.miller(ll));
                       
        
        temp = PAIR256.G1mul(Vprime, _y);
        temp.sub(V);
       
        
	FP48 right=PAIR256.fexp(PAIR256.ate(pk.get_g2x(), temp));
        
                
        if(left.equals(right)){
            //System.out.println("left: "+left);
            //System.out.println("right: "+right);
            return true;
        }
        else{
            //System.out.println("left: "+left);
            //System.out.println("right: "+right);
            return false;
        }
        }
        catch(NoSuchAlgorithmException e){
            Logger.getLogger(SDHABC.class.getName()).log(Level.SEVERE, null, e);
        } catch (Exception ex) {
            Logger.getLogger(SDHABC.class.getName()).log(Level.SEVERE, null, ex);
            throw new Exception("AND proof: "+ex.getMessage());            
        }
        
        return false;
    }
    
    public boolean proofOfANY(ABCpk pk, ABCcred cred, int threshold, String[] Aprime) throws Exception{
        try{
        MessageDigest H = MessageDigest.getInstance("SHA-512");
        RAND RNG = new RAND();
        BIG r,y,_r,_y,_ty,_s;        
        BIG order = new BIG(ROM.CURVE_Order);
        
        //testing new intersection function
        ArrayList<String>[] result = findSame(threshold, cred.get_A(), Aprime);
        BIG[] m;     //remains in A
        BIG[] w = new BIG[result[0].size()];    //intersected set
        BIG[] barw; //remains in A'
               
        
        //threshold must >0
        for(int i=0;i<w.length;i++){
            byte[] temp = H.digest(result[0].get(i).getBytes());
            byte[] hash = new byte[80];
                for(int j=0;j<hash.length;j++){
                    if(j<temp.length)
                        hash[j]=temp[j];
                    else
                        hash[j]=0x00;
                }
            w[i] = BIG.fromBytes(hash);
            w[i].mod(order);
        }
        w = convertToAlphas(w,order);   
        
        if(threshold<cred.get_A().length){            
            m = syntheticDivision(cred.get_alphas(),w)[0];
        }
        else{
            m = new BIG[1];
            m[0] = new BIG();
            m[0].one();
        }             
        
        if(result[1].size()>0){
            barw = new BIG[result[1].size()];
            for(int i=0;i<barw.length;i++){
                byte[] temp = H.digest(result[1].get(i).getBytes());
                byte[] hash = new byte[80];
                for(int j=0;j<hash.length;j++){
                    if(j<temp.length)
                        hash[j]=temp[j];
                    else
                        hash[j]=0x00;
                }
                barw[i] = BIG.fromBytes(hash);
                barw[i].mod(order);
            }
            
            barw = convertToAlphas(barw,order);        
        }
        else{
            barw = new BIG[1];
            barw[0] = new BIG();
            barw[0].one();
        }
                
        SecureRandom rand = new SecureRandom();
        RNG.clean();
	RNG.seed(100,rand.generateSeed(100));
        
        //prover sends commitment and witnesses        
        BIG[] _omega = new BIG[w.length];
        
        r = BIG.randomnum(order,RNG);
        y = BIG.randomnum(order,RNG);
        BIG yinv=new BIG(y);
        yinv.invmodp(order);
        _r = BIG.randomnum(order,RNG);
        _y = BIG.randomnum(order,RNG);
        _ty = BIG.randomnum(order,RNG);
        _s = BIG.randomnum(order,RNG);
        
        ECP V1 = PAIR256.G1mul(cred.get_v(), BIG.modmul(BIG.modmul(r, r, order), yinv, order));
        ECP V2 = PAIR256.G1mul(V1, _y);
        
        ECP M = PAIR256.G1mul(pk.get_a0(),m[0]);
        for(int i=1;i<m.length;i++){
            M.add(PAIR256.G1mul(pk.get_a()[i], m[i]));
        }
        M = PAIR256.G1mul(M, r);
        
        ECP Y1 = PAIR256.G1mul(V1, _ty);
        Y1.add(PAIR256.G1mul(pk.get_c(), _r));
        Y1.add(PAIR256.G1mul(pk.get_b(), _s));        
        
        ECP barW = PAIR256.G1mul(pk.get_a0(),barw[0]);
        for(int i=1;i<barw.length;i++){
            barW.add(PAIR256.G1mul(pk.get_a()[i], barw[i]));
        }
        BIG rinv = new BIG(r);
        rinv.invmodp(order);
        barW=PAIR256.G1mul(barW, rinv);
        
        _omega[0] = BIG.randomnum(order,RNG);
        ECP8 Y2 = PAIR256.G2mul(pk.get_g2(),_omega[0]);
        for(int i=1;i<_omega.length;i++){
            _omega[i] = BIG.randomnum(order,RNG);
            Y2.add(PAIR256.G2mul(pk.get_X()[i], _omega[i]));
        }                
        
        //verifier replies a challenge
        BIG e = BIG.randomnum(order,RNG);
        
      
        //prover sends response
        //\hat{r}=\tilde{r}+e^2r^2
        _r.add(BIG.modmul(e, BIG.modmul(r,r,order), order));    
        _r.mod(order);
        //\hat{y}=\tilde{y}+e^2y
        _y.add(BIG.modmul(e, y, order));        
        _y.mod(order);
        //\hat{t_y}=\tilde{t_y}-e^2ty
        _ty.sub(BIG.modmul(e, BIG.modmul(cred.get_t(), y, order), order));  
        _ty.mod(order);
        //\hat{s}=\tilde{s}+e^2sr^2
        _s.add(BIG.modmul(e, BIG.modmul(cred.get_s(),BIG.modmul(r,r,order),order), order));
        _s.mod(order);
        
        for(int i=0;i<_omega.length;i++){
            _omega[i].add(BIG.modmul(e, BIG.modmul(w[i],r,order), order));
            _omega[i].mod(order);
        }
        
        //verifier checks        
        //new checking, only 3 pairings
        FP48[] ll=PAIR256.initmp();	       
        
        ECP8 temp2 = PAIR256.G2mul(pk.get_g2(), _omega[0]);        
        for(int i=1;i<_omega.length;i++){
            temp2.add(PAIR256.G2mul(pk.get_X()[i], _omega[i]));            
        }
        temp2.sub(Y2);
        barW.add(M);
        PAIR256.another(ll,temp2, barW);
        
        BIG[] z = new BIG[Aprime.length];
        for(int i=0;i<Aprime.length;i++){
            byte[] temp = H.digest(Aprime[i].getBytes());
            byte[] hash = new byte[80];
                for(int j=0;j<hash.length;j++){
                    if(j<temp.length)
                        hash[j]=temp[j];
                    else
                        hash[j]=0x00;
                }
            z[i] = BIG.fromBytes(hash);  
            z[i].mod(order);
        }
        z = convertToAlphas(z, order);
        ECP temp=PAIR256.G1mul(pk.get_a()[0], z[0]);
        for(int i=1;i<z.length;i++){
            temp.add(PAIR256.G1mul(pk.get_a()[i], z[i]));            
        }
        temp=PAIR256.G1mul(temp, e);
        temp.neg();
        temp.sub(Y1);
        temp.add(PAIR256.G1mul(pk.get_b(), _s));
        temp.add(PAIR256.G1mul(pk.get_c(), _r));
        temp.add(PAIR256.G1mul(V1, _ty));
        
	PAIR256.another(ll,pk.get_g2(), temp);
	FP48 left=PAIR256.fexp(PAIR256.miller(ll));
                       
        
        temp = PAIR256.G1mul(V1, _y);
        temp.sub(V2);
       
        
	FP48 right=PAIR256.fexp(PAIR256.ate(pk.get_g2x(), temp));
        
                
        if(left.equals(right))
            return true;
        else{
            return false;
        }
        }
        catch(NoSuchAlgorithmException e){
            Logger.getLogger(SDHABC.class.getName()).log(Level.SEVERE, null, e);
        } catch (Exception ex) {
            Logger.getLogger(SDHABC.class.getName()).log(Level.SEVERE, null, ex);
            throw new Exception("ANY proof: "+ex.getMessage());            
        }
        
        return false;
    }
    
    public boolean proofOfNAND(ABCpk pk, ABCcred cred, String[] Aprime) throws Exception{
        try{
        MessageDigest H = MessageDigest.getInstance("SHA-512");
        RAND RNG = new RAND();
        BIG r,y,_r,_y,_ty,_s;        
        BIG order = new BIG(ROM.CURVE_Order);
        BIG[] m, d;
        
        //if threshold doesn't met, exception thrown
        //so, we don't need to perform a check anymore
        ArrayList<String>[] result = findNotSame(Aprime.length,cred.get_A(),Aprime);                
                
        //those not-same attributes        
        BIG[] z = new BIG[result[0].size()];
        for(int i=0;i<z.length;i++){   
            byte[] temp = H.digest(result[0].get(i).getBytes());
                byte[] hash = new byte[80];
                for(int j=0;j<hash.length;j++){
                    if(j<temp.length)
                        hash[j]=temp[j];
                    else
                        hash[j]=0x00;
                }
            z[i] = BIG.fromBytes(hash);
            z[i].mod(order);
        }
                
        BIG[][] division = syntheticDivision(cred.get_alphas(),
                                             convertToAlphas(z, order));
        m = division[0]; //answer
        d = division[1]; //remainder
          
        SecureRandom rand = new SecureRandom();
        RNG.clean();
	RNG.seed(100,rand.generateSeed(100));
        
        BIG[] _d = new BIG[d.length];
        
        r = BIG.randomnum(order,RNG);
        y = BIG.randomnum(order,RNG);
        BIG yinv=new BIG(y);
        yinv.invmodp(order);
        _r = BIG.randomnum(order,RNG);
        _y = BIG.randomnum(order,RNG);
        _ty = BIG.randomnum(order,RNG);
        _s = BIG.randomnum(order,RNG);
        
        ECP V1 = PAIR256.G1mul(cred.get_v(), BIG.modmul(r, yinv, order));
        ECP V2 = PAIR256.G1mul(V1, _y);
        
        _d[0] = BIG.randomnum(order,RNG);
        ECP D = PAIR256.G1mul(pk.get_a0(),_d[0]);
        for(int i=1;i<_d.length;i++){
            _d[i] = BIG.randomnum(order,RNG);
            D.add(PAIR256.G1mul(pk.get_a()[i], _d[i]));
        }
        
        ECP M = PAIR256.G1mul(pk.get_a0(),m[0]);
        for(int i=1;i<m.length;i++){
            M.add(PAIR256.G1mul(pk.get_a()[i], m[i]));
        }
        M = PAIR256.G1mul(M, r);
        
        ECP Y = PAIR256.G1mul(V1, _ty);
        Y.add(PAIR256.G1mul(pk.get_c(), _r));
        Y.add(PAIR256.G1mul(pk.get_b(), _s));        
        
        //verifier replies a challenge
        BIG e = BIG.randomnum(order,RNG);        
      
        //prover sends response
        //\hat{r}=\tilde{r}+er
        _r.add(BIG.modmul(e, r, order));
        _r.mod(order);        
        //\hat{y}=\tilde{y}+ey
        _y.add(BIG.modmul(e, y, order));        
        _y.mod(order);
        //\hat{t_y}=\tilde{t_y}-ety
        _ty.sub(BIG.modmul(e, BIG.modmul(cred.get_t(), y, order), order));  
        _ty.mod(order);
        //\hat{s}=\tilde{s}+esr
        _s.add(BIG.modmul(e, BIG.modmul(cred.get_s(),r,order), order));
        _s.mod(order);
        
        for(int i=0;i<_d.length;i++){
            _d[i].add(BIG.modmul(e, BIG.modmul(d[i],r,order), order));
            _d[i].mod(order);
        }
        
        //verifier checks        
        //new checking, only 3 pairings
        ECP temp = PAIR256.G1mul(pk.get_a0(), _d[0]);
        for(int i=1;i<_d.length;i++){
            temp.add(PAIR256.G1mul(pk.get_a()[i], _d[i]));            
        }
        temp.sub(D);
        
        if(temp.is_infinity()){
            return false;
        }
        
        FP48[] ll=PAIR256.initmp();
        temp.add(PAIR256.G1mul(pk.get_b(), _s));
        temp.add(PAIR256.G1mul(pk.get_c(), _r));
        temp.add(PAIR256.G1mul(V1, _ty));        
        temp.sub(Y);
	PAIR256.another(ll,pk.get_g2(), temp);
	
        ECP temp1 = PAIR256.G1mul(M, e);        
        
        z = new BIG[Aprime.length];
        for(int i=0;i<Aprime.length;i++){
            byte[] htemp = H.digest(Aprime[i].getBytes());
                byte[] hash = new byte[80];
                for(int j=0;j<hash.length;j++){
                    if(j<htemp.length)
                        hash[j]=htemp[j];
                    else
                        hash[j]=0x00;
                }
            z[i] = BIG.fromBytes(hash);
            z[i].mod(order);
        }
        z = convertToAlphas(z, order);
        
        ECP8 temp2 = PAIR256.G2mul(pk.get_g2(), z[0]);
        for(int i=1;i<z.length;i++){
            temp2.add(PAIR256.G2mul(pk.get_X()[i], z[i]));            
        }
        
        PAIR256.another(ll,temp2, temp1);                        
	FP48 left=PAIR256.fexp(PAIR256.miller(ll));
                       
        
        temp = PAIR256.G1mul(V1, _y);
        temp.sub(V2);
       
        
	FP48 right=PAIR256.fexp(PAIR256.ate(pk.get_g2x(), temp));
        
                
        if(left.equals(right)){
            return true;
        }
        else{
            return false;
        }
        }
        catch(NoSuchAlgorithmException e){
            Logger.getLogger(SDHABC.class.getName()).log(Level.SEVERE, null, e);
        } catch (Exception ex) {
            Logger.getLogger(SDHABC.class.getName()).log(Level.SEVERE, null, ex);
            throw new Exception("NAND proof: "+ex.getMessage());            
        }
        
        return false;
    }
    
    public boolean proofOfNANY(ABCpk pk, ABCcred cred, int threshold, String[] Aprime) throws Exception{
        try{
        MessageDigest H = MessageDigest.getInstance("SHA-512");
        RAND RNG = new RAND();
        BIG r,y,_r,_y,_ty,_s;        
        BIG order = new BIG(ROM.CURVE_Order);
        BIG[] m, d;
        
        //if threshold doesn't met, exception thrown
        //so, we don't need to perform a check anymore
        ArrayList<String>[] result = findNotSame(threshold,cred.get_A(),Aprime);                
        
        //those not-same attributes        
        BIG[] barw = new BIG[result[0].size()];
        for(int i=0;i<barw.length;i++){    
            byte[] temp = H.digest(result[0].get(i).getBytes());
                byte[] hash = new byte[80];
                for(int j=0;j<hash.length;j++){
                    if(j<temp.length)
                        hash[j]=temp[j];
                    else
                        hash[j]=0x00;
                }
            barw[i] = BIG.fromBytes(hash);
            barw[i].mod(order);
        }
        barw = convertToAlphas(barw, order);
        
        //those remaining attributes in A', can be mixture of same and not same
        BIG[] w = new BIG[result[1].size()];
        for(int i=0;i<w.length;i++){  
            byte[] temp = H.digest(result[1].get(i).getBytes());
                byte[] hash = new byte[80];
                for(int j=0;j<hash.length;j++){
                    if(j<temp.length)
                        hash[j]=temp[j];
                    else
                        hash[j]=0x00;
                }
            w[i] = BIG.fromBytes(hash);
            w[i].mod(order);
        }
        w = convertToAlphas(w, order);
                
        BIG[][] division = syntheticDivision(cred.get_alphas(),
                                             barw);
        m = division[0]; //answer
        d = division[1]; //remainder
        
                
        SecureRandom rand = new SecureRandom();
        RNG.clean();
	RNG.seed(100,rand.generateSeed(100));
        
        BIG[] _d = new BIG[d.length];
        BIG[] _barw = new BIG[barw.length];
        
        r = BIG.randomnum(order,RNG);
        y = BIG.randomnum(order,RNG);
        BIG yinv=new BIG(y);
        yinv.invmodp(order);
        _r = BIG.randomnum(order,RNG);
        _y = BIG.randomnum(order,RNG);
        _ty = BIG.randomnum(order,RNG);
        _s = BIG.randomnum(order,RNG);
        
        ECP V1 = PAIR256.G1mul(cred.get_v(), BIG.modmul(BIG.modmul(r,r,order), yinv, order));
        ECP V2 = PAIR256.G1mul(V1, _y);
        
        
        ECP M = PAIR256.G1mul(pk.get_a0(),m[0]);
        for(int i=1;i<m.length;i++){
            M.add(PAIR256.G1mul(pk.get_a()[i], m[i]));
        }
        M = PAIR256.G1mul(M, r);
        
        ECP W = PAIR256.G1mul(pk.get_a0(),w[0]);
        for(int i=1;i<w.length;i++){
            W.add(PAIR256.G1mul(pk.get_a()[i], w[i]));
        }
        BIG rinv = new BIG(r);
        rinv.invmodp(order);
        W = PAIR256.G1mul(W, rinv);
        
        _d[0] = BIG.randomnum(order,RNG);
        ECP D = PAIR256.G1mul(pk.get_a0(),_d[0]);
        for(int i=1;i<_d.length;i++){
            _d[i] = BIG.randomnum(order,RNG);
            D.add(PAIR256.G1mul(pk.get_a()[i], _d[i]));
        }
        
        _barw[0] = BIG.randomnum(order,RNG);
        ECP8 Y2 = PAIR256.G2mul(pk.get_X()[0],_barw[0]);
        for(int i=1;i<_barw.length;i++){
            _barw[i] = BIG.randomnum(order,RNG);
            Y2.add(PAIR256.G2mul(pk.get_X()[i], _barw[i]));
        }
                
        ECP Y1 = PAIR256.G1mul(V1, _ty);
        Y1.add(PAIR256.G1mul(pk.get_c(), _r));
        Y1.add(PAIR256.G1mul(pk.get_b(), _s));        
        
        //verifier replies a challenge
        BIG e = BIG.randomnum(order,RNG);        
      
        //prover sends response
        //\hat{r}=\tilde{r}+e^2r^2
        _r.add(BIG.modmul(e, BIG.modmul(r,r,order), order));
        _r.mod(order);        
        //\hat{y}=\tilde{y}+e^2y
        _y.add(BIG.modmul(e, y, order));        
        _y.mod(order);
        //\hat{t_y}=\tilde{t_y}-e^2ty
        _ty.sub(BIG.modmul(e, BIG.modmul(cred.get_t(), y, order), order));  
        _ty.mod(order);
        //\hat{s}=\tilde{s}+e^2sr^2
        _s.add(BIG.modmul(e, BIG.modmul(cred.get_s(),BIG.modmul(r,r,order),order), order));
        _s.mod(order);
            
        
        for(int i=0;i<_barw.length;i++){
            _barw[i].add(BIG.modmul(e, BIG.modmul(barw[i],r,order), order));
            _barw[i].mod(order);
        }
        
        for(int i=0;i<_d.length;i++){
            _d[i].add(BIG.modmul(e, BIG.modmul(d[i],BIG.modmul(r,r,order),order), order));
            _d[i].mod(order);
        }
        
        //verifier checks        
        //new checking, only 3 pairings
        ECP temp = PAIR256.G1mul(pk.get_a0(), _d[0]);
        for(int i=1;i<_d.length;i++){
            temp.add(PAIR256.G1mul(pk.get_a()[i], _d[i]));            
        }
        temp.sub(D);
        
        if(temp.is_infinity()){
            return false;
        }
        
        FP48[] ll=PAIR256.initmp();
        temp.add(PAIR256.G1mul(pk.get_b(), _s));
        temp.add(PAIR256.G1mul(pk.get_c(), _r));
        temp.add(PAIR256.G1mul(V1, _ty));        
        temp.sub(Y1);
        
        
        BIG[] z = new BIG[Aprime.length];
        for(int i=0;i<Aprime.length;i++){
            byte[] htemp = H.digest(Aprime[i].getBytes());
                byte[] hash = new byte[80];
                for(int j=0;j<hash.length;j++){
                    if(j<htemp.length)
                        hash[j]=htemp[j];
                    else
                        hash[j]=0x00;
                }
            z[i] = BIG.fromBytes(hash);
            z[i].mod(order);
        }
        z = convertToAlphas(z, order);
        
        ECP tempp = PAIR256.G1mul(pk.get_a0(), z[0]);
        for(int i=1;i<z.length;i++){
            tempp.add(PAIR256.G1mul(pk.get_a()[i], z[i]));            
        }
        temp.sub(PAIR256.G1mul(tempp, e));
        
	PAIR256.another(ll,pk.get_g2(), temp);
	
        
        ECP8 temp2=PAIR256.G2mul(pk.get_g2(), _barw[0]);        
        for(int i=1;i<_barw.length;i++){
            temp2.add(PAIR256.G2mul(pk.get_X()[i], _barw[i]));            
        }
        temp2.sub(Y2);
        
        W.add(M);
        PAIR256.another(ll,temp2, W);                        
	FP48 left=PAIR256.fexp(PAIR256.miller(ll));
                       
        
        temp = PAIR256.G1mul(V1, _y);
        temp.sub(V2);
       
        
	FP48 right=PAIR256.fexp(PAIR256.ate(pk.get_g2x(), temp));
        
                
        if(left.equals(right)){
            return true;
        }
        else{
            return false;
        }
        }
        catch(NoSuchAlgorithmException e){
            Logger.getLogger(SDHABC.class.getName()).log(Level.SEVERE, null, e);
        } catch (Exception ex) {
            Logger.getLogger(SDHABC.class.getName()).log(Level.SEVERE, null, ex);
            throw new Exception("NANY proof: "+ex.getMessage());            
        }
        
        return false;
    }
    
    public ArrayList[] findSame(int threshold, String[] A, String[] Aprime) throws Exception{
        if(threshold<1){
            throw new Exception("Threshold must fall in between 1 <= threshold <= |A'|.");
        }
        if(threshold>Aprime.length){
            throw new Exception("You fail to meet the condition threshold<=|A'|.");
        }
        if(A.length<Aprime.length){
            throw new Exception("You fail to meet the condition |A|>=|A'|.");
        }
        
        ArrayList same = new ArrayList(threshold);    //the intersected set
        ArrayList _A = new ArrayList(A.length);   
        ArrayList _Aprime = new ArrayList(Aprime.length);
        int k=-1,m=0,n=0;
        
        //convert to vector (not yet done: the sequence should be randomized)
        for(int i=0;i<A.length;i++){
            _A.add(A[i]);
        }
        for(int i=0;i<Aprime.length;i++){
            _Aprime.add(Aprime[i]);
        }
        
        for(int i=0;i<Aprime.length;i++){
            k=_A.indexOf(Aprime[i]);
            if(k>-1){   //attr found
                m++;
                same.add(Aprime[i]);
                if(m==threshold){    //not yet enough attr
                    break;
                }                
            }
            else{   //no attr found, do nothing
                
            }
        }
        
        if(m==threshold){
            _Aprime.removeAll(same);
            //_A.removeAll(same);
            //_A.trimToSize();
            same.trimToSize();
            _Aprime.trimToSize();
            
            ArrayList[] result = new ArrayList[2];
            //result[0]=_A;
            result[0]=same;
            result[1]=_Aprime;
            
            return result;
        }
        else{
            throw new Exception("Not enough intersected attributes.");
        }
    }
    
    public ArrayList[] findNotSame(int threshold, String[] A, String[] Aprime) throws Exception{
        if(threshold<1){
            throw new Exception("Threshold must fall in between 1 <= threshold <= |A'|.");
        }
        if(threshold>Aprime.length){
            throw new Exception("You fail to meet the condition threshold<=|A'|.");
        }
        if(A.length<Aprime.length){
            throw new Exception("You fail to meet the condition |A|>=|A'|.");
        }
        
        ArrayList xsame = new ArrayList(threshold);    //the intersected set
        ArrayList _A = new ArrayList(A.length);   
        ArrayList _Aprime = new ArrayList(Aprime.length);
        int k=-1,m=0,n=0;
        
        //convert to vector (not yet done: the sequence should be randomized)
        for(int i=0;i<A.length;i++){
            _A.add(A[i]);
        }
        for(int i=0;i<Aprime.length;i++){
            _Aprime.add(Aprime[i]);
        }
        
        for(int i=0;i<Aprime.length;i++){
            k=_A.indexOf(Aprime[i]);
            if(k>-1){   //attr found, do nothing                                   
                                        
            }
            else{   //no attr found
                m++;
                xsame.add(Aprime[i]);
                if(m==threshold){
                    break;
                }
            }
        }
        
        if(m==threshold){
            _Aprime.removeAll(xsame);
            xsame.trimToSize();
            _Aprime.trimToSize();
            
            ArrayList[] result = new ArrayList[2];
            result[0]=xsame;
            result[1]=_Aprime;
            
            return result;
        }
        else{
            throw new Exception("Not enough non-intersected attributes.");
        }
    }  
        
    public BIG[] convertToAlphas(BIG[] A,BIG order){   
        BIG[] L = new BIG[A.length+1];
        
        for(int i=0;i<L.length;i++){
            L[i] = new BIG();
            L[i].zero();
        }
        
        L[A.length].one();
        
        if(A.length==1){
            L[0] = A[0];
            return L;
        }
        
        L[0] = BIG.modmul(A[0],A[1], order);
        //L[1].zero();
        L[1].add(A[0]);
        L[1].mod(order);
        L[1].add(A[1]);
        L[1].mod(order);
        
        for(int i=2;i<A.length;i++){
            for(int j=i;j>0;j--){
                if(j==i){
                    L[i].add(L[i-1]);
                    L[i].mod(order);
                    L[i].add(A[i]);
                    L[i].mod(order);
                    //L[i]=L[i-1].add(A[i]);                    
                }  
                else if(j==1){ 
                    L[j] = BIG.modmul(L[j], A[i], order);
                    L[j].add(L[j-1]);
                    L[j].mod(order);
                    //L[j] = L[j].multiply(A[i]).add(L[j-1]);
                    
                    L[0] = BIG.modmul(L[0], A[i], order);
                    //L[0] = L[0].multiply(A[i]);
                }
                else{
                    L[j] = BIG.modmul(L[j], A[i], order);
                    L[j].add(L[j-1]);                    
                    L[j].mod(order);
                }
            }
        }
        
        return L;
    }  
    
    /*
    * Old function, buggy where overflow happens in BIG class
    * @return BIG[] with last element BIG[1] as the remainder.
    *
    public BIG[][] syntheticDivisionBIG(BIG[] dvdend, BIG[] dvsor){
        BIG order = new BIG(ROM.CURVE_Order);
        BIG[] ans = new BIG[dvdend.length];        
        for(int i=0;i<dvdend.length;i++){
            ans[i] = new BIG(dvdend[dvdend.length-i-1]);
        }        
        
        BIG[] xdvsor = new BIG[dvsor.length];
        for(int i=0;i<dvsor.length;i++){
            xdvsor[i] = new BIG(dvsor[dvsor.length-i-1]);
        }                
        
        BIG normalizer = new BIG(xdvsor[0]);
        normalizer.invmodp(order);
        for (int i = 0; i < dvdend.length - (dvsor.length - 1); i++) {            
            ans[i]=BIG.modmul(ans[i], normalizer, order);            
            
            BIG coef = new BIG(ans[i]);
            
            if (!coef.iszilch()) {
                for (int j = 1; j < dvsor.length; j++){
                    ans[i+j].sub(BIG.modmul(coef, xdvsor[j], order));
                    ans[i+j].mod(order);
                }
                    //ans[i + j] += -divisor[j] * coef;
            }
        }
        
        int separator = ans.length - (dvsor.length - 1);
        BIG[] temp1 = Arrays.copyOfRange(ans, 0, separator);
        BIG[] temp2 = Arrays.copyOfRange(ans, separator, ans.length);
        
        ans = new BIG[temp1.length];
        for(int i=0;i<temp1.length;i++){
            ans[i] = temp1[temp1.length-i-1];
        }
        
        xdvsor = new BIG[temp2.length];
        for(int i=0;i<temp2.length;i++){
            xdvsor[i] = temp2[temp2.length-i-1];
        } 
        
        return new BIG[][]{
            ans, xdvsor
        };
    }
    */
    
    /*
    * @return BIG[] with last element BIG[1] as the remainder.
    */
    public BIG[][] syntheticDivision(BIG[] dvdend, BIG[] dvsor){
        //BIG order = new BIG(ROM.CURVE_Order);
        BigInteger order = toBigInteger(new BIG(ROM.CURVE_Order));        
        
        //BIG[] ans = new BIG[dvdend.length];        
        BigInteger[] ans = new BigInteger[dvdend.length];
        
        for(int i=0;i<dvdend.length;i++){            
            ans[i] = toBigInteger(dvdend[dvdend.length-i-1]);
        }        
        
        //BIG[] xdvsor = new BIG[dvsor.length];
        BigInteger[] xdvsor = new BigInteger[dvsor.length];
        for(int i=0;i<dvsor.length;i++){            
            xdvsor[i] = toBigInteger(dvsor[dvsor.length-i-1]);
        }                
        
        //BIG normalizer = new BIG(xdvsor[0]);
        
        BigInteger normalizer = xdvsor[0].modInverse(order);
        //normalizer.invmodp(order);
        
        for (int i = 0; i < dvdend.length - (dvsor.length - 1); i++) {            
            //ans[i]=BIG.modmul(ans[i], normalizer, order);            
            ans[i]=ans[i].multiply(normalizer).mod(order);
            
            //BIG coef = new BIG(ans[i]);
            BigInteger coef = ans[i];
            
            //if (!coef.iszilch()) {
            if (!coef.equals(BigInteger.ZERO)) {
                for (int j = 1; j < dvsor.length; j++){
                    //ans[i+j].sub(BIG.modmul(coef, xdvsor[j], order));
                    ans[i+j] = ans[i+j].subtract(coef.multiply(xdvsor[j]).mod(order)).mod(order);
                    //ans[i+j].mod(order);
                }
            }
        }
        
        int separator = ans.length - (dvsor.length - 1);
        //BIG[] temp1 = Arrays.copyOfRange(ans, 0, separator);
        BigInteger[] temp1 = Arrays.copyOfRange(ans, 0, separator);
        //BIG[] temp2 = Arrays.copyOfRange(ans, separator, ans.length);
        BigInteger[] temp2 = Arrays.copyOfRange(ans, separator, ans.length);
        
        //ans = new BIG[temp1.length];
        BIG[] answer = new BIG[temp1.length];
        for(int i=0;i<temp1.length;i++){
            answer[i] = toBIG(temp1[temp1.length-i-1]);
            //ans[i] = temp1[temp1.length-i-1];
        }
        
        BIG[] remainder = new BIG[temp2.length];
        //xdvsor = new BIG[temp2.length];
        for(int i=0;i<temp2.length;i++){
            remainder[i] = toBIG(temp2[temp2.length-i-1]);
            //xdvsor[i] = temp2[temp2.length-i-1];
        } 
        
        return new BIG[][]{
            //ans, xdvsor
            answer, remainder
        };
    }
    
    public BigInteger toBigInteger(BIG num){
        return new BigInteger(num.toString().replaceFirst("^0+(?!$)", ""),16);
    }
    
    public BIG toBIG(BigInteger num){
        String str = num.toString(16);
        String prefix="";
        String order = new BIG(ROM.CURVE_Order).toString();
        if(str.length()<order.length()){
            
            for(int i=0;i<order.length()-str.length();i++){
                prefix+="0";
            }
            prefix+=str;
        }
        
        byte[] val = new byte[prefix.length() / 2];
        for (int i = 0; i < val.length; i++) {
            int index = i * 2;
            int j = Integer.parseInt(prefix.substring(index, index + 2), 16);
            val[i] = (byte) j;
        }
        return BIG.fromBytes(val);
    }
    
    /*
    public int rho(String[] A, String attr){
        
        for(int i=0;i<A.length;i++){
            if(A[i].equals(attr)){
                return i;
            }
        }
        
        return -1;
    }
    
    public String[][] findSameXsame(boolean SAME, int threshold, String[] A, String[] Aprime){
        String[] same;
        String[] xsame;
        String temp ="!";
        String xtemp ="!";
        int length = A.length;
        int k=-1,j=0,i=0;
                
        if(Aprime.length>=length){
            length = Aprime.length;
            while(i<length){
                k=rho(A,Aprime[i]);
                if(SAME){
                if(k>-1 && j<threshold){
                    j++;
                    temp=temp.concat(","+A[k]);     
                    
                }
                else if(k>-1 && j>=threshold){
                    xtemp = xtemp.concat(","+Aprime[i]);
                }
                else{
                    xtemp = xtemp.concat(","+Aprime[i]);
                }
                }
                else{
                    if(k==-1 && j<threshold){
                    j++;
                    temp=temp.concat(","+Aprime[i]);     
                    
                    }
                    else if(k==-1 && j>=threshold){
                    xtemp = xtemp.concat(","+Aprime[i]);
                    }
                    else{
                    xtemp = xtemp.concat(","+A[k]);
                    }
                }
                i++;
            }
        }
        else{
            length = Aprime.length;
            while(i<length){
                k=rho(Aprime,A[i]);
                
                if(SAME){
                if(k>-1 && j<threshold){
                    j++;
                    temp=temp.concat(","+A[k]);
                }
                else if(k>-1 && j>=threshold){
                    xtemp = xtemp.concat(","+Aprime[i]);
                }
                else{
                    xtemp = xtemp.concat(","+Aprime[i]);
                }
                }
                else{
                    if(k==-1 && j<threshold){
                    j++;
                    temp=temp.concat(","+Aprime[i]);     
                    
                    }
                    else if(k==-1 && j>=threshold){
                    xtemp = xtemp.concat(","+Aprime[i]);
                    }
                    else{
                    xtemp = xtemp.concat(","+A[k]);
                    }
                }
                i++;
            }
        }
        
        if(j==threshold){
            //System.out.println("threshold met, temp: "+temp+", xtemp: "+xtemp);
            temp.trim();
            temp = temp.split("!")[1];
            String[] tt = temp.split(",");
            same = new String[tt.length-1]; 
            for(i=1;i<tt.length;i++){                        
                same[i-1]=tt[i];            
            }
        
            if(xtemp.length()>1){
                xtemp.trim();
                xtemp = xtemp.split("!")[1];
                tt = xtemp.split(",");
                xsame = new String[tt.length-1]; 
                for(i=1;i<tt.length;i++){                        
                    xsame[i-1]=tt[i];            
                }
            }
            else{
                xsame=null;
            }
            String[][] result = new String[2][];
            result[0]=same;
            result[1]=xsame;
            return result;
        }
        else{
            //System.out.println("threshold="+threshold+", j="+j+", threshold not met:"+temp);
            return null;
        }
    }
    */  
    
}

