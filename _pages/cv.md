---
layout: archive
title: "CV"
permalink: /cv/
author_profile: true
redirect_from:
  - /resume
---

{% include base_path %}

Education
======
* M.S. in Cybersecurity at Ynov, Bordeaux, 2023
* B.S. in Computer Science at Université Bretagne-Sud, Vannes, 2020

Work experience
======
* 2023-2024: Cyber Security Engineer
  * Improvement of cloud monitoring and security
  * Helping set up a Vulnerability Disclosure Policy
  * L3 Support

* 2021-2023: Cyberdefense Analyst
  * Cyber governance (registration file, risk analysis, etc)
  * User awareness on cyber risks
  * Control of user stations
  * Organizationial and compliance audit
  
Skills
======
* Network, web & system security
* Penetration testing & audit
* Cyber governance
* Linux
* Python

Publications
======
  <ul>{% for post in site.publications reversed %}
    {% include archive-single-cv.html %}
  {% endfor %}</ul>
  
Talks
======
  <ul>{% for post in site.talks reversed %}
    {% include archive-single-talk-cv.html  %}
  {% endfor %}</ul>
  
Teaching
======
  <ul>{% for post in site.teaching reversed %}
    {% include archive-single-cv.html %}
  {% endfor %}</ul>
