# Using Helix responsibly

Helix looks at pages anyone can open. That does not make every use of it
fair or lawful. This page says what Helix is for, what it is not for, and
what the two privacy laws most of its users fall under ask of you. It is
written in plain words and it is not legal advice.

## What Helix is for

- Checking your own accounts and leaks, and deleting what you no longer
  want (`helix --me`).
- Security work you are allowed to do: a penetration test, a bug bounty or a
  red-team exercise with the scope agreed in writing.
- Investigations by people whose job it is: journalists, researchers, trust
  and safety teams, fraud and legal teams, law enforcement acting within
  their powers.
- Teaching and learning open source investigation.

## What Helix is not for

- Finding or following a person who has not agreed and whom you have no
  lawful reason to look into: an ex-partner, a neighbour, a stranger.
- Harassment, doxxing, stalking, or building a profile of someone to
  pressure or embarrass them.
- Deciding things about a person (hiring, renting, lending) from accounts
  that merely share a username. A username can belong to different people
  on different sites. Helix grades how strongly accounts are tied together
  for that reason, and a LOW grade means "same name, nothing more".

## What is built in

- **A stated purpose.** `--purpose "..."` is sealed into the evidence record,
  the report and the watch history. Without it they say "not stated". If a
  record will be shown to anyone, state the purpose.
- **A left-out list.** Anyone can ask that their username or address is
  never looked up. Helix refuses those names before sending any request, and
  no option turns that off. See [LEFT_OUT.md](LEFT_OUT.md).
- **No messages to the person.** Helix never uses password-reset, one-time
  code or SMS endpoints, so a scan cannot trigger an email or a text to the
  person searched.
- **No guessing.** A site that did not answer is never reported as "no
  account", and an account is reported only after the site refused made-up
  names. A wrong hit about a real person does harm; that is why zero false
  positives is the rule the rest of Helix is built around.
- **Leaks are metadata only.** The breach check says which breaches an
  address appears in. It never fetches or shows passwords or leaked records.
- **Phone numbers are opt-in and need a purpose.** `--phone` never runs as
  part of `--all`, refuses to start without `--purpose`, only looks at the
  number you typed, and hides its middle digits in reports. It reads what the
  number itself says and, with `--breach`, the breach lists. A phone number
  is rarely something its owner published, so the "made public by the
  person" exemption of the DPDP Act will usually not cover it: use it on
  your own number, with the owner's agreement, or with a lawful reason.
- **Adult sites are off by default.**
- **Your own exit.** `helix --me` shows where to delete each account and
  writes an erasure request for sites that offer no delete button.

## The GDPR (EU and UK), in plain words

If you are in the EU or UK, or the person you look up is, and you are not
doing it for a purely personal or household reason, the GDPR applies to you
even though the pages are public.

- **You need a lawful basis.** For most investigative work that is
  "legitimate interests": you have a real need, the lookup is necessary for
  it, and the need is not outweighed by the person's interests. Write that
  reasoning down before you start. Consent is the other common basis; if you
  rely on it, be able to show it.
- **Take only what you need.** Scan the names you have a reason to scan.
  Leave out modules you do not need. Do not keep results longer than the
  purpose requires.
- **Be accurate.** Do not present a same-name account as the person's
  without corroboration. Keep the grades and the "no clear answer" counts in
  what you pass on.
- **Keep it safe.** Results are personal data. Store them where others
  cannot read them and delete them when you are done.
- **The person has rights.** They can ask what you hold about them, ask you
  to correct or erase it, and object. In most cases you must also tell them
  you hold their data within a month, unless an exemption applies (for
  example where telling them would defeat a lawful investigation).
- **Some data needs more care.** Health, religion, politics, sexual
  orientation and similar categories, and data about children, have stricter
  rules. A username on a site about one of those topics can reveal them.
- **Journalism and research** have their own exemptions, which differ by
  country. Check yours.

## India's Digital Personal Data Protection Act, 2023, in plain words

The DPDP Act covers digital personal data processed in India, and processing
outside India that is connected with offering goods or services to people in
India.

- **It does not cover** personal data that the person has made publicly
  available themselves, or that is public because a law requires it to be.
  A profile someone published under their own name is the usual example.
  This is narrower than it sounds: data other people published about
  someone, or data leaked in a breach, was not made public by that person.
- **It does not cover** processing by an individual for a personal or
  domestic purpose. Checking your own accounts is that. Looking into another
  person for work is not.
- **Where it applies, you need consent or a "legitimate use"** listed in the
  Act (for example a legal obligation, or a medical emergency). There is no
  general "legitimate interests" ground as in the GDPR.
- **The person has rights** to know what is processed, to have it corrected
  and erased, and to complain. `helix --me` writes an erasure request that
  names section 12 for this.
- **Children's data** needs verifiable consent from a parent or guardian,
  and tracking or behavioural monitoring of children is barred.
- Breach lists are a special case: leaked data was not made public by the
  person. Use `--breach` on your own addresses, or where the person agreed.

## Before you scan someone else

Ask yourself, and write the answers into `--purpose` and your own notes:

1. Why do I need this, and is a scan necessary for it?
2. What gives me the right: their consent, a contract, a law, a legitimate
   interest I can defend?
3. What is the least I can collect, and how long will I keep it?
4. What happens to this person if I am wrong about an account?

If you cannot answer the second question, do not run the scan.

## If someone scanned you

See [LEFT_OUT.md](LEFT_OUT.md) to be left out of future lookups, and run
`helix --me` to find and delete accounts you no longer want.
