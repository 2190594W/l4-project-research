# Formal language definition

## Constants, Expressions, Syntax, Types & Context

<need to define an array?>

_Values (v)_  
>*n* 􏰁::= Integers ℕ  
*b* 􏰁::= False | True 𝔹  
*d* ::= Dates 𝔻   <perhaps not a constant? Date ⇒ Integer milliseconds>  
*s* ::= Strings 𝕊  
*l* 􏰁::= ⦰ | v::𝕃

_Values/Variables_  
> *e* ::=􏰁 *n* | *d* | *s* | *l* | *μ*  

_Expressions_  
> | greaterThan (*e*, *e*) | lessThan (*e*, *e*) | equal (*e*, *e*)  
| greaterThanOrEqual (*e*, *e*) | lessThanOrEqual (*e*, *e*)  
| or(*e*, *e*) | and(*e*, *e*)

_Statements_
> | let *μ* be *e* in *e* | (λ*μ*•*e*) | *e* $ *e*

_Types_  
> *t*:𝕋 ::= ℤ | 𝔻 | 𝕊 | 𝔹 | 𝕃 | 𝕋 → 𝕋  

_Context_  
> Γ ::=􏰁 Γ, (*e*:*t*) | ∅

## Typing Rules

Intro-Nat:     &nbsp; &nbsp; &nbsp; *n* : ℤ

Intro-F:       &nbsp; &nbsp; &nbsp; False : 𝔹

Intro-T:       &nbsp; &nbsp; &nbsp; True : 𝔹

Intro-Date:    &nbsp; &nbsp; &nbsp; May 26, 2019 : Date

Intro-String:  &nbsp; &nbsp; &nbsp; "Lorem Ipsum" : String

Var:           &nbsp; &nbsp; &nbsp; *μ*:*T* ϵ Γ ⇒ *μ*:*T*

List:          &nbsp; &nbsp; &nbsp; *Nil\_t* | (*x*:*t*) :: *\_tl\_t*

And:           &nbsp; &nbsp; &nbsp; (Γ ⊢ *a* : 𝔹 &nbsp; &nbsp; &nbsp; Γ ⊢ *b* : 𝔹) ⇒ Γ ⊢ and(*a*, *b*) : 𝔹

Or:            &nbsp; &nbsp; &nbsp; (Γ ⊢ *a* : 𝔹 &nbsp; &nbsp; &nbsp; Γ ⊢ *b* : 𝔹) ⇒ Γ ⊢ or(*a*, *b*) : 𝔹

GreaterThan    &nbsp; &nbsp; &nbsp; (Γ ⊢ *a*:*T₁* &nbsp; &nbsp; &nbsp; Γ ⊢ *b*:*T₁* &nbsp; &nbsp; &nbsp; [*T₁* ϵ {𝔻, ℕ}]) ⇒ Γ ⊢ greaterThan(*a*, *b*):𝔹

LessThan    &nbsp; &nbsp; &nbsp; (Γ ⊢ *a*:*T₁* &nbsp; &nbsp; &nbsp; Γ ⊢ *b*:*T₁* &nbsp; &nbsp; &nbsp; [*T₁* ϵ {𝔻, ℕ}]) ⇒ Γ ⊢ lessThan(*a*, *b*):𝔹

Equal    &nbsp; &nbsp; &nbsp; (Γ ⊢ *a*:*T₁* &nbsp; &nbsp; &nbsp; Γ ⊢ *b*:*T₁* &nbsp; &nbsp; &nbsp; [*T₁* ϵ {𝕊, 𝔻, ℕ, 𝔹}]) ⇒ Γ ⊢ equal(*a*, *b*):𝔹

GreaterThanOrEqual    &nbsp; &nbsp; &nbsp; (Γ ⊢ *a*:*T₁* &nbsp; &nbsp; &nbsp; Γ ⊢ *b*:*T₁* &nbsp; &nbsp; &nbsp; [*T₁* ϵ {𝔻, ℕ}]) ⇒ Γ ⊢ greaterThanOrEqual(*a*, *b*):𝔹

LessThanOrEqual    &nbsp; &nbsp; &nbsp; (Γ ⊢ *a*:*T₁* &nbsp; &nbsp; &nbsp; Γ ⊢ *b*:*T₁* &nbsp; &nbsp; &nbsp; [*T₁* ϵ {𝔻, ℕ}]) ⇒ Γ ⊢ lessThanOrEqual(*a*, *b*):𝔹

<Need a string comparison?>

Let:           &nbsp; &nbsp; &nbsp; (*μ* : T₁ &nbsp; &nbsp; &nbsp; Γ ⊢ *e*₁ : T₁  &nbsp; &nbsp; &nbsp; Γ, (*μ* : T₁) ⊢ *e*₂ : T₂) ⇒ Γ ⊢ let *μ* be *e*₁ in *e*₂:T₂

## Substitution

(*μ*)[*e*/*x*]􏰁 ::= {(*e* &nbsp; &nbsp; *x* ≡ 􏰀*μ*) / (*x* &nbsp; &nbsp; *x* ≢ 􏰀*μ*) }

(and(*a*, *b*))[*e*/*x*]􏰁 ::= and((*a*)[*e*/*x*] (*b*)[*e*/*x*])  
(or(*a*, *b*))[*e*/*x*]􏰁 ::= or((*a*)[*e*/*x*] (*b*)[*e*/*x*])  
(greaterThan(*a*, *b*))[*e*/*x*]􏰁 ::= greaterThan(\(*a*\)[*e*/*x*] \(*b*\)[*e*/*x*])  
(lessThan(*a*, *b*))[*e*/*x*]􏰁 ::= lessThan(\(*a*\)[*e*/*x*] \(*b*\)[*e*/*x*])  
(equal(*a*, *b*))[*e*/*x*]􏰁 ::= equal(\(*a*\)[*e*/*x*] \(*b*\)[*e*/*x*])  
(greaterThanOrEqual(*a*, *b*))[*e*/*x*]􏰁 ::= greaterThanOrEqual(\(*a*\)[*e*/*x*] \(*b*\)[*e*/*x*])  
(lessThanOrEqual(*a*, *b*))[*e*/*x*]􏰁 ::= lessThanOrEqual(\(*a*\)[*e*/*x*] \(*b*\)[*e*/*x*])  
(let *μ* be *e*₁ in *e*₂)[*e*/*x*] ::=􏰁 let *μ* be \(*e*₁\)[*e*/*x*] in \(*e*₂\)[*e*/*x*]

## Big Step Semantics

INT/NAT () ⇒ *n* ⇓ *n*  
BOOL () ⇒ *b* ⇓ *b*

OR (*a* ⇓ *a′*  &nbsp; &nbsp; *b* ⇓ *b′*) ⇒ or(*a*, *b*)⇓*a′* ∨ *b′*  
AND (*a* ⇓ *a′*  &nbsp; &nbsp; *b* ⇓ *b′*) ⇒ and(*a*, *b*) ⇓ *a′* ∧ *b′*  
GT (*a* ⇓ *a′*  &nbsp; &nbsp; *b* ⇓ *b′*) ⇒ greaterThan(*a*, *b*) ⇓ *a′* > *b′*  
LT (*a* ⇓ *a′*  &nbsp; &nbsp; *b* ⇓ *b′*) ⇒ lessThan(*a*, *b*) ⇓ *a′* < *b′*  
EQ (*a* ⇓ *a′*  &nbsp; &nbsp; *b* ⇓ *b′*) ⇒ equal(*a*, *b*) ⇓ *a′* ≡ *b′*  
GTE (*a* ⇓ *a′*  &nbsp; &nbsp; *b* ⇓ *b′*) ⇒ greaterThanOrEqual(*a*, *b*) ⇓ *a′* ≧ *b′*  
LTE (*a* ⇓ *a′*  &nbsp; &nbsp; *b* ⇓ *b′*) ⇒ lessThanOrEqual(*a*, *b*) ⇓ *a′* ≦ *b′*  


## Interpretation

PolicyLang → Python (PyOpenABE)

⟦ℤ⟧ ::= `int`  
⟦*n*⟧ ::=􏰁 `int(n)`  
⟦𝔹⟧ ::= `bool`  
⟦True⟧ ::= `True`  
⟦False⟧ ::= `False`  
⟦𝔻⟧ ::= `datetime.date`  
⟦*d*⟧ ::= `datetime.date(d)`  
⟦𝕊⟧ ::= `str`  
⟦*s*⟧ ::= `str(s)`  
⟦𝕃⟧ ::= `list`  
⟦*l*⟧ ::= `[l]`  
⟦or(*a*, *b*)⟧ 􏰁::= ⟦*a*⟧ `or` ⟦*b*⟧  
⟦and(*a*,*b*)⟧ 􏰁::= ⟦*a*⟧ `and` ⟦*b*⟧  
⟦greaterThan(*a*,*b*)⟧ 􏰁::= ⟦*a*⟧ `>` ⟦*b*⟧  
⟦lessThan(*a*,*b*)⟧ 􏰁::= ⟦*a*⟧ `<` ⟦*b*⟧  
⟦equal(*a*,*b*)⟧ 􏰁::= ⟦*a*⟧ `==` ⟦*b*⟧  
⟦greaterThanEqual(*a*,*b*)⟧ 􏰁::= ⟦*a*⟧ `>=` ⟦*b*⟧  
⟦lessThanEqual(*a*,*b*)⟧ 􏰁::= ⟦*a*⟧ `<=` ⟦*b*⟧  
⟦let *μ* be *e₁* in *e₂*⟧ ::= 􏰁⟦(*e₂*)[*μ*/*e₁*]⟧
