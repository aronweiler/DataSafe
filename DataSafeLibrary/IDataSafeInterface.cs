using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.ServiceModel;

namespace DataSafeLibrary
{
	[ServiceContract(Name = "DataSafeInterface", Namespace = "http://www.aronweiler.com/2008/1/DataSafeInterface")]
	public interface IDataSafeInterface
	{
		[OperationContract]
		bool IsServiceAcceptingRequests();

		[OperationContract(IsOneWay = true)]
		void AddFileToProcess(string fileName);
	}
}
