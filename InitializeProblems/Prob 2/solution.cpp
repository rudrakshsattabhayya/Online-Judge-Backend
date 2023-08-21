#include <bits/stdc++.h>
using namespace std;
 
int main(){
    ios_base::sync_with_stdio(false);
    cin.tie(NULL);
    cout.tie(NULL);
    
    int t=1;
    cin>>t;
    while(t--){
        string s;
        cin>>s;
        int n=s.size();

        for(int i=0;i<n;i++){
            if(s[i] == '?'){
                s[i]='0';
            }else break;
        }
        for(int i=n-1;i>=0;i--){
            if(s[i] == '?'){
                s[i]='1';
            }else break;
        }



        for(int i=1;i<n;i++){
            if(s[i]=='?'){
                s[i]=s[i-1];
            }
        }

        cout<<s<<"\n";
    }
    
}