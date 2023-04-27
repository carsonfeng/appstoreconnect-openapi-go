# CiBuildRunRelationships

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**Builds** | Pointer to [**AppEncryptionDeclarationRelationshipsBuilds**](AppEncryptionDeclarationRelationshipsBuilds.md) |  | [optional] 
**Workflow** | Pointer to [**CiBuildRunRelationshipsWorkflow**](CiBuildRunRelationshipsWorkflow.md) |  | [optional] 
**Product** | Pointer to [**AppRelationshipsCiProduct**](AppRelationshipsCiProduct.md) |  | [optional] 
**SourceBranchOrTag** | Pointer to [**CiBuildRunRelationshipsSourceBranchOrTag**](CiBuildRunRelationshipsSourceBranchOrTag.md) |  | [optional] 
**DestinationBranch** | Pointer to [**CiBuildRunRelationshipsSourceBranchOrTag**](CiBuildRunRelationshipsSourceBranchOrTag.md) |  | [optional] 
**PullRequest** | Pointer to [**CiBuildRunRelationshipsPullRequest**](CiBuildRunRelationshipsPullRequest.md) |  | [optional] 

## Methods

### NewCiBuildRunRelationships

`func NewCiBuildRunRelationships() *CiBuildRunRelationships`

NewCiBuildRunRelationships instantiates a new CiBuildRunRelationships object
This constructor will assign default values to properties that have it defined,
and makes sure properties required by API are set, but the set of arguments
will change when the set of required properties is changed

### NewCiBuildRunRelationshipsWithDefaults

`func NewCiBuildRunRelationshipsWithDefaults() *CiBuildRunRelationships`

NewCiBuildRunRelationshipsWithDefaults instantiates a new CiBuildRunRelationships object
This constructor will only assign default values to properties that have it defined,
but it doesn't guarantee that properties required by API are set

### GetBuilds

`func (o *CiBuildRunRelationships) GetBuilds() AppEncryptionDeclarationRelationshipsBuilds`

GetBuilds returns the Builds field if non-nil, zero value otherwise.

### GetBuildsOk

`func (o *CiBuildRunRelationships) GetBuildsOk() (*AppEncryptionDeclarationRelationshipsBuilds, bool)`

GetBuildsOk returns a tuple with the Builds field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetBuilds

`func (o *CiBuildRunRelationships) SetBuilds(v AppEncryptionDeclarationRelationshipsBuilds)`

SetBuilds sets Builds field to given value.

### HasBuilds

`func (o *CiBuildRunRelationships) HasBuilds() bool`

HasBuilds returns a boolean if a field has been set.

### GetWorkflow

`func (o *CiBuildRunRelationships) GetWorkflow() CiBuildRunRelationshipsWorkflow`

GetWorkflow returns the Workflow field if non-nil, zero value otherwise.

### GetWorkflowOk

`func (o *CiBuildRunRelationships) GetWorkflowOk() (*CiBuildRunRelationshipsWorkflow, bool)`

GetWorkflowOk returns a tuple with the Workflow field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetWorkflow

`func (o *CiBuildRunRelationships) SetWorkflow(v CiBuildRunRelationshipsWorkflow)`

SetWorkflow sets Workflow field to given value.

### HasWorkflow

`func (o *CiBuildRunRelationships) HasWorkflow() bool`

HasWorkflow returns a boolean if a field has been set.

### GetProduct

`func (o *CiBuildRunRelationships) GetProduct() AppRelationshipsCiProduct`

GetProduct returns the Product field if non-nil, zero value otherwise.

### GetProductOk

`func (o *CiBuildRunRelationships) GetProductOk() (*AppRelationshipsCiProduct, bool)`

GetProductOk returns a tuple with the Product field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetProduct

`func (o *CiBuildRunRelationships) SetProduct(v AppRelationshipsCiProduct)`

SetProduct sets Product field to given value.

### HasProduct

`func (o *CiBuildRunRelationships) HasProduct() bool`

HasProduct returns a boolean if a field has been set.

### GetSourceBranchOrTag

`func (o *CiBuildRunRelationships) GetSourceBranchOrTag() CiBuildRunRelationshipsSourceBranchOrTag`

GetSourceBranchOrTag returns the SourceBranchOrTag field if non-nil, zero value otherwise.

### GetSourceBranchOrTagOk

`func (o *CiBuildRunRelationships) GetSourceBranchOrTagOk() (*CiBuildRunRelationshipsSourceBranchOrTag, bool)`

GetSourceBranchOrTagOk returns a tuple with the SourceBranchOrTag field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetSourceBranchOrTag

`func (o *CiBuildRunRelationships) SetSourceBranchOrTag(v CiBuildRunRelationshipsSourceBranchOrTag)`

SetSourceBranchOrTag sets SourceBranchOrTag field to given value.

### HasSourceBranchOrTag

`func (o *CiBuildRunRelationships) HasSourceBranchOrTag() bool`

HasSourceBranchOrTag returns a boolean if a field has been set.

### GetDestinationBranch

`func (o *CiBuildRunRelationships) GetDestinationBranch() CiBuildRunRelationshipsSourceBranchOrTag`

GetDestinationBranch returns the DestinationBranch field if non-nil, zero value otherwise.

### GetDestinationBranchOk

`func (o *CiBuildRunRelationships) GetDestinationBranchOk() (*CiBuildRunRelationshipsSourceBranchOrTag, bool)`

GetDestinationBranchOk returns a tuple with the DestinationBranch field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetDestinationBranch

`func (o *CiBuildRunRelationships) SetDestinationBranch(v CiBuildRunRelationshipsSourceBranchOrTag)`

SetDestinationBranch sets DestinationBranch field to given value.

### HasDestinationBranch

`func (o *CiBuildRunRelationships) HasDestinationBranch() bool`

HasDestinationBranch returns a boolean if a field has been set.

### GetPullRequest

`func (o *CiBuildRunRelationships) GetPullRequest() CiBuildRunRelationshipsPullRequest`

GetPullRequest returns the PullRequest field if non-nil, zero value otherwise.

### GetPullRequestOk

`func (o *CiBuildRunRelationships) GetPullRequestOk() (*CiBuildRunRelationshipsPullRequest, bool)`

GetPullRequestOk returns a tuple with the PullRequest field if it's non-nil, zero value otherwise
and a boolean to check if the value has been set.

### SetPullRequest

`func (o *CiBuildRunRelationships) SetPullRequest(v CiBuildRunRelationshipsPullRequest)`

SetPullRequest sets PullRequest field to given value.

### HasPullRequest

`func (o *CiBuildRunRelationships) HasPullRequest() bool`

HasPullRequest returns a boolean if a field has been set.


[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)


