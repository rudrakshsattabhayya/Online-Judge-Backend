#include <bits/stdc++.h>

#define all(x) (x).begin(), (x).end()
#define allr(x) (x).rbegin(), (x).rend()
#define gsize(x) (int)((x).size())

const char nl = '\n';
typedef long long ll;
typedef long double ld;

using namespace std;

const int maxn = 1000000;

vector<int> g[maxn];
int s[maxn];
ll ans = 0;

void dfs(int v, int p = -1)
{
	vector<ll> a;
	s[v] = 1;

	for (int u : g[v])
	{
		if (u == p)
			continue;
		dfs(u, v);
		s[v] += s[u];

		a.push_back(s[u]);
	}

	vector<ll> dp(s[v]);
	ll cs = 0;
	for (int x : a)
	{
		for (ll i = cs + x; i >= 0; i--)
		{
			for (ll pr = min(cs, i); pr >= max(0LL, i - x); pr--)
			{
				ll j = i - pr;
				dp[i] = max(dp[i], dp[pr] + j * (cs - pr) + pr * (x - j));
			}
		}
		cs += x;
	}

	ans += *max_element(all(dp));
	dp.clear();
	a.clear();
}

int main()
{
	ios::sync_with_stdio(0);
	cin.tie(0);
	int t = 1;
	cin >> t;
	while (t--)
	{
		int n;
		cin >> n;
		for (int i = 1; i < n; i++)
		{
			int x;
			cin >> x;
			g[x - 1].push_back(i);
		}

		dfs(0);

		cout << ans << nl;
	}
}