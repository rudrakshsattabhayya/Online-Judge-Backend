#include <bits/stdc++.h>
using namespace std;

int main(){
    int t=1;
    cin>>t;
    while(t--){
        int n;
        cin>>n;
        vector<int> v(n);
        for(int i=0;i<n;i++){
            cin>>v[i];
        }
        bool ans = false;
        sort(v.begin(), v.end());
        for(int i=0;i<v.size()-1;i++){
            if(v[i] == v[i+1]){
                ans=true;
                break;
            }
        }

        if(ans){
            cout<<"True\n";
        }else{
            cout<<"False\n";
        }
    }
}