#include<bits/stdc++.h>
using namespace std;
int t;
int main()
{
    cin>>t;
    while(t--)
    {
    	int n,ans1=0,ans2=0;
    	string s,t;
    	cin>>n>>s>>t;
    	for(int i=0;i<n;i++)
    	{
    		if(s[i]!=t[i])
    			ans1++;
			if(s[i]!=t[n-i-1])
				ans2++;
		}
    	cout<<min(2*ans1-(ans1%2),max(2,2*ans2-!(ans2%2)))<<endl;
	}
}