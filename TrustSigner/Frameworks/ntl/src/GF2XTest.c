
#include <NTL/GF2X.h>
#include <fstream>

NTL_CLIENT

struct wd {
   int amt;

   wd(int x) { amt = x; } 
};

#define WD(x,y)  wd(x) << (y)

ostream& operator<<(ostream& s, const wd& w)
{
   s.width(w.amt);
   return s;
}

int main()
{
   std::ofstream outFile;
   long n;
   GF2X a, b, c, c1, ss, ss1, tt, tt1;
   double t;
   long iter, i;
   printf("Starting GF2XTest");

   outFile.open ("XXX");
   outFile << WD(12,"n") << WD(12,"OldGCD") <<  WD(12,"GCD") << WD(12,"OldXGCD")
           << WD(12, "XGCD") << "\n";

   //cout.precision(3);
   //cout.setf(ios::scientific);

   printf("Round: ");
   for (n = 32; n <= (1L << 18); n = n << 3) {
      printf("%d ",n);
      random(a, n);
      random(b, n);
      OldGCD(c, a, b);
      GCD(c1, a, b);
      OldXGCD(c, ss, tt, a, b);
      XGCD(c1, ss1, tt1, a, b);
      if (c1 != c || ss1 != ss || tt1 != tt ||
          ss*a + tt*b != c) {
         outFile << "**** GF2XTest FAILED!\n";
         return 1;
      }

      outFile << WD(12,n); 

      iter = 0;
      do {
         iter = iter ? (2*iter) : 1;
         t = GetTime();
         for (i = 0; i < iter; i++)
            OldGCD(c, a, b);
         t = GetTime()-t;
      } while (t < 0.5);

      outFile << WD(12,t/iter);

      iter = 0;
      do {
         iter = iter ? (2*iter) : 1;
         t = GetTime();
         for (i = 0; i < iter; i++)
            GCD(c, a, b);
         t = GetTime()-t;
      } while (t < 0.5);

      outFile << WD(12,t/iter);

      iter = 0;
      do {
         iter = iter ? (2*iter) : 1;
         t = GetTime();
         for (i = 0; i < iter; i++)
            OldXGCD(c, ss, tt, a, b);
         t = GetTime()-t;
      } while (t < 0.5);

      outFile << WD(12,t/iter);

      iter = 0;
      do {
         iter = iter ? (2*iter) : 1;
         t = GetTime();
         for (i = 0; i < iter; i++)
            XGCD(c, ss, tt, a, b);
         t = GetTime()-t;
      } while (t < 0.5);

      outFile << WD(12,t/iter);

      outFile << "\n";
   }

   return 0;
}
