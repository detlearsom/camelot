# Phase 1 - CaMeL -> CTL Translation

For every CaMeL policy in the original AgentDojo benchmark, produce an
equivalent or a bit stricter CTL formula (when possible). 

## Source material

CaMeL policies in
[`src/camel/pipeline_elements/security_policies/`](../../src/camel/pipeline_elements/security_policies/):

- [slack.md](slack.md) — Slack agent
- [banking.md](banking.md) — Banking agent
- [travel.md](travel.md) — Travel booking agent
- [workspace.md](workspace.md) — Cloud workspace (email + calendar + drive) agent

CTL policies live in
[`src/camel/ext/ctl_policies/`](../../src/camel/ext/ctl_policies/).


## Side-effecting policy overlap

For functions that write or send data, CaMeL makes an explicit allow/deny decision via the `SecurityPolicyEngine` subclasses. This table counts how well CTL's formulas capture the same logic.

<table>
<thead>
<tr>
  <th rowspan="2">Suite</th>
  <th rowspan="2">CaMeL Policies</th>
  <th colspan="3">Security</th>
  <th colspan="3">Confidentiality</th>
</tr>
<tr>
  <th>Full</th><th>Partial</th><th>None</th>
  <th>Full</th><th>Partial</th><th>None</th>
</tr>
</thead>
<tbody>
<tr><td><a href="slack.md">Slack</a></td>        <td>7</td>  <td>3</td><td>1</td><td>3</td> <td>3</td><td>0</td><td>4</td></tr>
<tr><td><a href="banking.md">Banking</a></td>    <td>5</td>  <td>5</td><td>0</td><td>0</td> <td>2</td><td>3</td><td>0</td></tr>
<tr><td><a href="travel.md">Travel</a></td>      <td>6</td>  <td>6</td><td>0</td><td>0</td> <td>5</td><td>0</td><td>1</td></tr>
<tr><td><a href="workspace.md">Workspace</a></td><td>10</td> <td>8</td><td>0</td><td>2</td> <td>6</td><td>0</td><td>4</td></tr>
<tr><td><strong>Total</strong></td><td><strong>28</strong></td> <td><strong>22</strong></td><td><strong>1</strong></td><td><strong>5</strong></td> <td><strong>16</strong></td><td><strong>3</strong></td><td><strong>9</strong></td></tr>
</tbody>
</table>

## Read-only output taint overlap

For functions that only read data, CaMeL never blocks the call but annotates each output value with fine-grained `Capabilities(sources, readers)`. CTL instead stamps a static trusted/untrusted label at call time. This table counts how well those two approaches agree.

<table>
<thead>
<tr>
  <th rowspan="2">Suite</th>
  <th rowspan="2">Total tools</th>
  <th colspan="3">Security</th>
  <th colspan="3">Confidentiality</th>
</tr>
<tr>
  <th>Full</th><th>Partial</th><th>None</th>
  <th>Full</th><th>Partial</th><th>None</th>
</tr>
</thead>
<tbody>
<tr><td><a href="travel.md">Travel</a></td>      <td>22</td> <td>17</td><td>5</td><td>0</td> <td>19</td><td>0</td><td>3</td></tr>
<tr><td><a href="banking.md">Banking</a></td>    <td>5</td>  <td>3</td><td>2</td><td>0</td>  <td>1</td><td>0</td><td>4</td></tr>
<tr><td><a href="workspace.md">Workspace</a></td><td>14</td> <td>1</td><td>13</td><td>0</td> <td>3</td><td>0</td><td>11</td></tr>
<tr><td><a href="slack.md">Slack</a></td>        <td>5</td>  <td>3</td><td>2</td><td>0</td>  <td>0</td><td>0</td><td>5</td></tr>
<tr><td><strong>Total</strong></td><td><strong>46</strong></td> <td><strong>24</strong></td><td><strong>22</strong></td><td><strong>0</strong></td> <td><strong>23</strong></td><td><strong>0</strong></td><td><strong>23</strong></td></tr>
</tbody>
</table>



## Gaps

`gaps.md` has the cross-suite findings: what CaMeL can express that CTL cannot, and what CTL gains that CaMeL cannot represent.
